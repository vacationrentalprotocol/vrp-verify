// VRP 1.0 candidate: the version a discovery document declares, the version a
// signed offer declares, and the two names of the signing operation
// (spec §2, §3, §5, §7, §9; ADR 0013, ADR 0017).
//
// The cases are the vrp-spec vectors, copied byte for byte from pull request
// 187: test/discovery-version/vectors.v1.0.json and test/vectors/06 to 15.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyCompactJws,
  verifyOffer,
  quoteChecks,
  safeToQuote,
  checkDiscoveryVersion,
  checkOfferVersion,
  checkDeclaredVersion,
  KNOWN_PROTOCOL_VERSIONS,
  SIGNATURE_ALGS,
  QuoteFailure,
  Reason,
  Status,
} from "../index.js";
import { DISCOVERY, signRawSegments, b64url, KID } from "./helpers.mjs";

const testDir = dirname(fileURLToPath(import.meta.url));
const read = (...parts) => JSON.parse(readFileSync(join(testDir, ...parts), "utf8"));
const versions = read("discovery-version", "vectors.v1.0.json");
const hostDomain = read("host-domain", "vectors.v0.1.json");
const base = read("vectors", "01-valid-fresh.json");

const context = (discovery) => ({
  domain: "example-host.invalid",
  hostOwnedLists: { icannRules: hostDomain.psl_icann_rules, specification13Tlds: hostDomain.icann_specification13_tlds },
  discovery,
  request: { ...base.input.offer.request },
  now: base.clock,
});

test("the known names are exactly the two of each", () => {
  assert.deepEqual([...KNOWN_PROTOCOL_VERSIONS], ["1.0", "0.1"]);
  assert.deepEqual([...SIGNATURE_ALGS], ["Ed25519", "EdDSA"]);
});

// ---------------------------------------------------------------------------
// The discovery document (§2, §7)

const accepted = new Set();
const refused = new Set();
for (const c of versions.discovery) {
  test(`discovery ${c.name}: ${c.expected.reason ?? "accepted"}`, () => {
    const reason = checkDiscoveryVersion(c.document);
    assert.equal(reason, c.expected.reason);
    if (reason === null) accepted.add(c.document.protocol_version);
    else refused.add(reason);

    // Through the gate: a valid, fresh, signed offer is safe to quote only
    // when the discovery document passes.
    const r = verifyOffer({ envelope: base.input, jwks: base.jwks, now: base.clock });
    assert.equal(r.status, Status.VERIFIED);
    const q = quoteChecks(r, context(c.document));
    assert.deepEqual(q.failures, c.expected.reason === null ? [] : [c.expected.reason]);
    assert.equal(safeToQuote(r, context(c.document)), c.expected.reason === null);
  });
}

test("discovery: both known versions are accepted and both failures occur", () => {
  assert.deepEqual([...accepted].sort(), ["0.1", "1.0"]);
  for (const reason of ["unsupported_version", "missing_protocol_version", "unexpected_protocol"]) {
    assert.ok(refused.has(reason), reason);
  }
});

for (const [name, document] of [["null", null], ["a string", "1.0"], ["an array", []], ["a number", 1]]) {
  test(`discovery that is ${name} is malformed, and the gate is closed`, () => {
    assert.equal(checkDiscoveryVersion(document), "malformed_discovery");
    const r = verifyOffer({ envelope: base.input, jwks: base.jwks, now: base.clock });
    assert.deepEqual(quoteChecks(r, context(document)).failures, [QuoteFailure.MALFORMED_DISCOVERY]);
  });
}

test("no discovery document: the gate is closed (discovery_unknown)", () => {
  const r = verifyOffer({ envelope: base.input, jwks: base.jwks, now: base.clock });
  const { discovery, ...without } = context(DISCOVERY);
  assert.deepEqual(quoteChecks(r, without), { ok: false, failures: [QuoteFailure.DISCOVERY_UNKNOWN] });
  assert.equal(safeToQuote(r, without), false);
  assert.deepEqual(quoteChecks(r, context(DISCOVERY)), { ok: true, failures: [] });
});

// ---------------------------------------------------------------------------
// Two declarations, checked separately (§2, §5)

for (const c of versions.pairs) {
  test(`pair ${c.name}: version ${c.expected.version_accepted ? "accepted" : "not accepted"}`, () => {
    const jws = verifyCompactJws(c.jws, versions.jwks);
    assert.equal(jws.valid, true, jws.reason);
    const discoveryReason = checkDiscoveryVersion(c.discovery);
    const offerReason = checkOfferVersion(jws.payload);
    assert.equal(discoveryReason, c.expected.discovery_reason, "discovery");
    assert.equal(offerReason, c.expected.offer_reason, "offer");
    assert.equal(discoveryReason === null && offerReason === null, c.expected.version_accepted);

    // The same through verifyOffer and the gate: the offer's own version
    // decides the offer's status, the document's version only the gate.
    const r = verifyOffer({ jws: c.jws, jwks: versions.jwks, now: jws.payload.generated_at });
    if (c.expected.offer_reason === null) assert.equal(r.status, Status.VERIFIED, `${r.status} (${r.code})`);
    else {
      assert.equal(r.status, Status.UNVERIFIABLE);
      assert.equal(r.code, c.expected.offer_reason);
    }
    const ctx = { ...context(c.discovery), request: { ...jws.payload.request }, now: jws.payload.generated_at };
    assert.equal(safeToQuote(r, ctx), c.expected.version_accepted);
  });
}

// ---------------------------------------------------------------------------
// The signed offer's version (§5, §9)

for (const [value, reason] of [
  ["1.0", null],
  ["0.1", null],
  ["0.2", "unsupported_version"],
  ["2.0", "unsupported_version"],
  ["1.0.0", "unsupported_version"],
  [" 1.0", "unsupported_version"],
  [1, "unsupported_version"],
  [0.1, "unsupported_version"],
  [null, "unsupported_version"],
  [["1.0"], "unsupported_version"],
  [undefined, "missing_protocol_version"],
]) {
  test(`signed protocol_version ${JSON.stringify(value) ?? "absent"}: ${reason ?? "accepted"}`, () => {
    assert.equal(checkDeclaredVersion(value), reason);
    const payload = structuredClone(base.input.offer);
    if (value === undefined) delete payload.protocol_version;
    else payload.protocol_version = value;
    const header = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: KID }));
    const jws = signRawSegments(header, b64url(JSON.stringify(payload)));
    const r = verifyOffer({ jws, jwks: base.jwks, now: base.clock });
    if (reason === null) {
      assert.equal(r.status, Status.VERIFIED);
    } else {
      // A genuine signature over an unknown version: Unknown, never Invalid, never quoted.
      assert.equal(r.status, Status.UNVERIFIABLE);
      assert.equal(r.code, reason);
      assert.equal(r.fresh, null);
      assert.equal(safeToQuote(r, context(DISCOVERY)), false);
    }
  });
}

test("the version is read from the signed payload, never from the unsigned envelope", () => {
  // The envelope says "1.0" beside an offer that says "0.2": the offer and the
  // signed payload agree, so only the signed value decides.
  const payload = { ...structuredClone(base.input.offer), protocol_version: "0.2" };
  const header = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: KID }));
  const jws = signRawSegments(header, b64url(JSON.stringify(payload)));
  const envelope = { ...base.input, protocol_version: "1.0", offer: payload, signature: { ...base.input.signature, jws } };
  const r = verifyOffer({ envelope, jwks: base.jwks, now: base.clock });
  assert.equal(r.status, Status.UNVERIFIABLE);
  assert.equal(r.code, Reason.UNSUPPORTED_VERSION);
});

// ---------------------------------------------------------------------------
// The two names of the signing operation (§3, §5; RFC 9864, RFC 8037)

for (const [alg, ok] of [
  ["Ed25519", true],
  ["EdDSA", true],
  ["ed25519", false],
  ["eddsa", false],
  ["EDDSA", false],
  ["ES256", false],
  ["HS256", false],
  ["none", false],
  ["", false],
  [null, false],
  [["EdDSA"], false],
]) {
  test(`protected header alg ${JSON.stringify(alg)}: ${ok ? "accepted" : "unexpected_alg"}`, () => {
    const header = b64url(JSON.stringify({ alg, typ: "JWT", kid: KID }));
    const jws = signRawSegments(header, b64url(JSON.stringify(base.input.offer)));
    const res = verifyCompactJws(jws, base.jwks);
    assert.equal(res.valid, ok);
    assert.equal(res.reason, ok ? null : Reason.UNEXPECTED_ALG);
    const r = verifyOffer({ jws, jwks: base.jwks, now: base.clock });
    assert.equal(r.status, ok ? Status.VERIFIED : Status.INVALID);
  });
}

test("a header without alg is refused", () => {
  const header = b64url(JSON.stringify({ typ: "JWT", kid: KID }));
  const jws = signRawSegments(header, b64url(JSON.stringify(base.input.offer)));
  assert.equal(verifyCompactJws(jws, base.jwks).reason, Reason.UNEXPECTED_ALG);
});
