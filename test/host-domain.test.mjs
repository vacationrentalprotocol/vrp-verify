// Host-owned domain (spec §2) and offer binding (§7), from 0.2.0.
//
// Parity with the vrp-spec host-domain conformance vectors, copied byte for
// byte into test/host-domain/vectors.v0.1.json, and the gate's fail-closed
// rules: without the domain the offer was fetched from, or without usable
// lists, an offer is never safe to quote. Every offer here is re-signed with
// the public conformance test key, so the signature stays valid and the GATE
// is what decides.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyOffer,
  safeToQuote,
  quoteChecks,
  QuoteFailure,
  Status,
  checkHostOwned,
  registrableDomain,
  icannRulesFromPsl,
  specification13FromGtlds,
  CLOSED_TLDS,
} from "../index.js";
import { resignedEnvelope } from "./helpers.mjs";

const testDir = dirname(fileURLToPath(import.meta.url));
const base = JSON.parse(readFileSync(join(testDir, "vectors", "01-valid-fresh.json"), "utf8"));
const doc = JSON.parse(readFileSync(join(testDir, "host-domain", "vectors.v0.1.json"), "utf8"));

const lists = { icannRules: doc.psl_icann_rules, specification13Tlds: doc.icann_specification13_tlds };
// 0.3.0: the gate also needs the stay asked for (§7); the base vector's signed request is it.
const REQUEST = { ...base.input.offer.request };
const CONTEXT = { domain: "example-host.invalid", hostOwnedLists: lists, request: REQUEST };
const verify = (envelope, now = base.clock) => verifyOffer({ envelope, jwks: base.jwks, now });

// An offer re-signed so that it names `domain` everywhere a node names itself.
const offerFor = (domain) =>
  verify(resignedEnvelope(base, (o) => {
    o.canonical_domain = domain;
    o.node_id = domain;
    o.booking.direct_booking_url = `https://${domain}/book`;
  }));

// ---------------------------------------------------------------------------
// Fail closed without context (the 0.2.0 change)

test("no context: a valid, fresh, signed offer is not safe to quote (domain_unknown, asked_stay_unknown)", () => {
  const r = verify(base.input);
  assert.equal(r.status, Status.VERIFIED);
  assert.deepEqual(quoteChecks(r), { ok: false, failures: [QuoteFailure.DOMAIN_UNKNOWN, QuoteFailure.ASKED_STAY_UNKNOWN] });
  assert.equal(safeToQuote(r), false);
});

test("a domain but no lists: unknown (host_owned_unknown, spec §2, §9)", () => {
  const r = verify(base.input);
  for (const hostOwnedLists of [
    undefined,
    null,
    {},
    { icannRules: [], specification13Tlds: [] },
    { icannRules: ["com"] },
    { icannRules: ["com"], specification13Tlds: [] },
  ]) {
    const q = quoteChecks(r, { domain: "example-host.invalid", hostOwnedLists, request: REQUEST });
    assert.deepEqual(q, { ok: false, failures: [QuoteFailure.HOST_OWNED_UNKNOWN] }, JSON.stringify(hostOwnedLists));
  }
});

test("a domain that is not a bare host name is unknown", () => {
  const r = verify(base.input);
  for (const domain of [
    "",
    "https://example-host.invalid",
    "example-host.invalid/",
    "example-host.invalid:443",
    "user@example-host.invalid",
    "example-host.invalid?x",
    "example host.invalid",
    42,
  ]) {
    const q = quoteChecks(r, { domain, hostOwnedLists: lists, request: REQUEST });
    assert.deepEqual(q, { ok: false, failures: [QuoteFailure.DOMAIN_UNKNOWN] }, String(domain));
  }
});

test("the domain is compared as a URL host (lowercased)", () => {
  const r = verify(base.input);
  assert.equal(safeToQuote(r, { domain: "EXAMPLE-HOST.invalid", hostOwnedLists: lists, request: REQUEST }), true);
});

test("with the domain and the lists, the valid vector passes", () => {
  assert.deepEqual(quoteChecks(verify(base.input), CONTEXT), { ok: true, failures: [] });
});

// ---------------------------------------------------------------------------
// §7 offer binding

test("an offer fetched from another domain is not that domain's offer (offer_domain_mismatch)", () => {
  const q = quoteChecks(verify(base.input), { domain: "other-host.invalid", hostOwnedLists: lists, request: REQUEST });
  assert.equal(q.ok, false);
  assert.deepEqual(q.failures, [QuoteFailure.OFFER_DOMAIN_MISMATCH]);
});

for (const v of doc.offer_binding.filter((x) => x.expected.reason !== "discovery_domain_mismatch")) {
  // discovery_names_another_domain concerns the discovery document, which
  // remains the caller's responsibility (README).
  test(`offer_binding vector: ${v.name}`, () => {
    const payload = JSON.parse(Buffer.from(v.input.signature.jws.split(".")[1], "base64url").toString("utf8"));
    const r = verifyOffer({ envelope: v.input, jwks: v.jwks, now: payload.generated_at });
    assert.equal(r.status === Status.VERIFIED, v.expected.signature_valid);
    const { failures } = quoteChecks(r, { domain: v.fetched_domain, hostOwnedLists: lists });
    assert.equal(
      failures.includes(QuoteFailure.OFFER_DOMAIN_MISMATCH),
      v.expected.reason === "offer_domain_mismatch",
      `${v.name}: ${failures}`,
    );
  });
}

// ---------------------------------------------------------------------------
// §2 host-owned domain: parity with the conformance vectors

test("the vectors name the same closed top-level domains as spec §2", () => {
  assert.deepEqual([...CLOSED_TLDS], doc.closed_tlds);
});

for (const group of ["host_owned", "real_world"]) {
  for (const v of doc[group]) {
    test(`${group} vector: ${JSON.stringify(v.canonical_domain)} -> ${v.expected.reason}`, () => {
      assert.equal(checkHostOwned(v.canonical_domain, lists), v.expected.reason);
      if (v.admitted_by_private_section) {
        // With the PRIVATE section the platform-issued name would wrongly pass.
        assert.equal(registrableDomain(v.canonical_domain, [...doc.psl_icann_rules, ...doc.psl_private_rules]), v.canonical_domain);
      }
      if (v.admitted_without_a_labels) {
        // Comparing rules without A-labels would wrongly admit it.
        const asciiRules = doc.psl_icann_rules.filter((r) => /^[\x00-\x7f]*$/.test(r));
        assert.equal(registrableDomain(v.canonical_domain, asciiRules), v.canonical_domain);
      }
    });

    test(`${group} vector through the gate: ${JSON.stringify(v.canonical_domain)}`, () => {
      const r = offerFor(v.canonical_domain);
      assert.equal(r.status, Status.VERIFIED, "signature must remain valid — the GATE decides");
      const q = quoteChecks(r, { domain: v.canonical_domain, hostOwnedLists: lists, request: REQUEST });
      if (v.expected.reason === null) {
        assert.deepEqual(q, { ok: true, failures: [] });
      } else {
        assert.equal(q.ok, false);
        assert.ok(q.failures.includes(v.expected.reason), `expected ${v.expected.reason}, got ${q.failures}`);
      }
    });
  }
}

// The names a platform hands out, a marketplace's name and a closed TLD:
// each signed with a key its own domain serves, each refused.
for (const [domain, reason] of [
  ["villa.wixsite.com", QuoteFailure.NOT_HOST_OWNED],
  ["villa.myshopify.com", QuoteFailure.NOT_HOST_OWNED],
  ["villa.airbnb.com", QuoteFailure.NOT_HOST_OWNED],
  ["villa.booking", QuoteFailure.CLOSED_TLD],
  ["villa.amazon", QuoteFailure.CLOSED_TLD],
]) {
  test(`a node under another party's domain is never safe to quote: ${domain}`, () => {
    const r = offerFor(domain);
    assert.equal(r.status, Status.VERIFIED);
    const ctx = { domain, hostOwnedLists: lists, request: REQUEST };
    assert.ok(quoteChecks(r, ctx).failures.includes(reason));
    assert.equal(safeToQuote(r, ctx), false);
    assert.equal(safeToQuote(r), false);
  });
}

// ---------------------------------------------------------------------------
// §2, §5.1 node URLs: the booking URL vectors

for (const v of doc.node_url.filter((x) => x.field === "direct_booking_url")) {
  test(`node_url vector (direct_booking_url): ${v.url} -> ${v.expected.reason}`, () => {
    const r = verify(resignedEnvelope(base, (o) => { o.booking.direct_booking_url = v.url; }));
    const { failures } = quoteChecks(r, CONTEXT);
    const bookingFailures = failures.filter((f) => f.startsWith("booking_url_"));
    if (v.expected.reason === null) assert.deepEqual(bookingFailures, []);
    else assert.equal(bookingFailures.length, 1, `expected a booking-URL failure, got ${failures}`);
  });
}

// ---------------------------------------------------------------------------
// The list parsers and the guard

test("checkHostOwned throws without usable lists, so a missing list never reads as a pass", () => {
  assert.throws(() => checkHostOwned("example.com", undefined), TypeError);
  assert.throws(() => checkHostOwned("example.com", { icannRules: [], specification13Tlds: [] }), TypeError);
});

test("icannRulesFromPsl takes only the ICANN section", () => {
  const psl = [
    "// header",
    "// ===BEGIN ICANN DOMAINS===",
    "com",
    "",
    "// a comment",
    "*.ck",
    "!www.ck",
    "// ===END ICANN DOMAINS===",
    "// ===BEGIN PRIVATE DOMAINS===",
    "wixsite.com",
    "// ===END PRIVATE DOMAINS===",
  ].join("\n");
  assert.deepEqual(icannRulesFromPsl(psl), ["com", "*.ck", "!www.ck"]);
  assert.equal(icannRulesFromPsl("com\nwixsite.com"), null);
  assert.equal(icannRulesFromPsl("// ===BEGIN ICANN DOMAINS===\n// ===END ICANN DOMAINS==="), null);
  assert.equal(icannRulesFromPsl(undefined), null);
});

test("specification13FromGtlds keeps the Specification 13 entries", () => {
  const json = {
    gTLDs: [
      { gTLD: "amazon", specification13: true },
      { gTLD: "com", specification13: false },
      { gTLD: "google", specification13: true },
      { gTLD: "hotels" },
    ],
  };
  assert.deepEqual(specification13FromGtlds(json), ["amazon", "google"]);
  // A list that marks nothing (a renamed field) is not a usable list.
  assert.equal(specification13FromGtlds({ gTLDs: [{ gTLD: "com", specification13: false }, { gTLD: "amazon" }] }), null);
  assert.equal(specification13FromGtlds({}), null);
  assert.equal(specification13FromGtlds({ gTLDs: [] }), null);
  assert.equal(specification13FromGtlds(null), null);
});
