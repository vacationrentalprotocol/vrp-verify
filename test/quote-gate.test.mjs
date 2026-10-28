// Safe-to-Quote gate (spec §7 offline-checkable conditions + §5.1 booking-URL
// rules). Each negative case re-signs a mutated payload with the public
// conformance test key, so the SIGNATURE stays valid and the gate — not the
// crypto — is what rejects the offer.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyOffer, safeToQuote, quoteChecks, QuoteFailure, Status } from "../index.js";
import { resignedEnvelope } from "./helpers.mjs";

const vectorsDir = join(dirname(fileURLToPath(import.meta.url)), "vectors");
const base = JSON.parse(readFileSync(join(vectorsDir, "01-valid-fresh.json"), "utf8"));

// Every case is evaluated at the base vector's own clock (offer is fresh).
const verify = (envelope) => verifyOffer({ envelope, jwks: base.jwks, now: base.clock });

test("baseline: the valid fresh vector passes the full gate", () => {
  const r = verify(base.input);
  assert.equal(r.status, Status.VERIFIED);
  const q = quoteChecks(r);
  assert.deepEqual(q, { ok: true, failures: [] });
  assert.equal(safeToQuote(r), true);
});

test("expired offer fails the gate with not_verified", () => {
  const v02 = JSON.parse(readFileSync(join(vectorsDir, "02-valid-expired.json"), "utf8"));
  const r = verifyOffer({ envelope: v02.input, jwks: v02.jwks, now: v02.clock });
  assert.equal(r.status, Status.EXPIRED);
  assert.deepEqual(quoteChecks(r).failures, [QuoteFailure.NOT_VERIFIED]);
  assert.equal(safeToQuote(r), false);
});

const NEGATIVE_CASES = [
  {
    name: "availability.available=false",
    mutate: (o) => { o.availability.available = false; },
    failure: QuoteFailure.AVAILABILITY_NOT_TRUE,
  },
  {
    name: "availability absent",
    mutate: (o) => { delete o.availability; },
    failure: QuoteFailure.AVAILABILITY_NOT_TRUE,
  },
  {
    name: "price.exact=false",
    mutate: (o) => { o.price.exact = false; },
    failure: QuoteFailure.PRICE_NOT_EXACT,
  },
  {
    name: "booking url missing",
    mutate: (o) => { delete o.booking; },
    failure: QuoteFailure.BOOKING_URL_MISSING,
  },
  {
    name: "booking url is http (not https)",
    mutate: (o) => { o.booking.direct_booking_url = "http://example-host.invalid/book"; },
    failure: QuoteFailure.BOOKING_URL_INVALID,
  },
  {
    name: "booking url is not an absolute URL",
    mutate: (o) => { o.booking.direct_booking_url = "/book?offer_id=x"; },
    failure: QuoteFailure.BOOKING_URL_INVALID,
  },
  {
    name: "booking url on a third-party domain",
    mutate: (o) => { o.booking.direct_booking_url = "https://evil.example/book"; },
    failure: QuoteFailure.BOOKING_URL_HOST_MISMATCH,
  },
  {
    name: "booking url host merely ends with the domain string (no dot boundary)",
    mutate: (o) => { o.booking.direct_booking_url = "https://notexample-host.invalid/book"; },
    failure: QuoteFailure.BOOKING_URL_HOST_MISMATCH,
  },
  {
    name: "agent_permission.may_quote_as_official_direct_offer=false",
    mutate: (o) => { o.agent_permission.may_quote_as_official_direct_offer = false; },
    failure: QuoteFailure.QUOTE_PERMISSION_NOT_GRANTED,
  },
  {
    name: "agent_permission absent",
    mutate: (o) => { delete o.agent_permission; },
    failure: QuoteFailure.QUOTE_PERMISSION_NOT_GRANTED,
  },
];

for (const c of NEGATIVE_CASES) {
  test(`gate rejects: ${c.name}`, () => {
    const r = verify(resignedEnvelope(base, c.mutate));
    assert.equal(r.status, Status.VERIFIED, "signature must remain valid — the GATE rejects");
    const q = quoteChecks(r);
    assert.equal(q.ok, false);
    assert.ok(q.failures.includes(c.failure), `expected ${c.failure}, got ${q.failures}`);
    assert.equal(safeToQuote(r), false);
  });
}

// §5.1 + §2 node URL: canonical_domain or www. + canonical_domain only.
test("gate accepts www. followed by canonical_domain", () => {
  const r = verify(resignedEnvelope(base, (o) => {
    o.booking.direct_booking_url = "https://www.example-host.invalid/checkout";
  }));
  assert.equal(safeToQuote(r), true);
});

test("gate accepts the default https port written out", () => {
  const r = verify(resignedEnvelope(base, (o) => {
    o.booking.direct_booking_url = "https://example-host.invalid:443/checkout";
  }));
  assert.equal(safeToQuote(r), true);
});

const NOT_NODE_URLS = [
  ["another name under canonical_domain", "https://airbnb.example-host.invalid/book", QuoteFailure.BOOKING_URL_HOST_MISMATCH],
  ["a name under www.", "https://book.www.example-host.invalid/book", QuoteFailure.BOOKING_URL_HOST_MISMATCH],
  ["canonical_domain as a label of another domain", "https://example-host.invalid.evil.example/book", QuoteFailure.BOOKING_URL_HOST_MISMATCH],
  ["a non-default port", "https://example-host.invalid:8443/book", QuoteFailure.BOOKING_URL_INVALID],
  ["userinfo", "https://user@example-host.invalid/book", QuoteFailure.BOOKING_URL_INVALID],
  ["userinfo with a password", "https://user:pw@example-host.invalid/book", QuoteFailure.BOOKING_URL_INVALID],
];

for (const [name, url, failure] of NOT_NODE_URLS) {
  test(`gate rejects a booking url that is not a node URL: ${name}`, () => {
    const r = verify(resignedEnvelope(base, (o) => { o.booking.direct_booking_url = url; }));
    assert.equal(r.status, Status.VERIFIED, "signature must remain valid — the GATE rejects");
    const q = quoteChecks(r);
    assert.ok(q.failures.includes(failure), `expected ${failure}, got ${q.failures}`);
    assert.equal(safeToQuote(r), false);
  });
}

test("gate is fail-closed when canonical_domain is absent", () => {
  const r = verify(resignedEnvelope(base, (o) => { delete o.canonical_domain; }));
  assert.equal(r.status, Status.VERIFIED);
  assert.ok(quoteChecks(r).failures.includes(QuoteFailure.BOOKING_URL_HOST_MISMATCH));
});

test("multiple failed conditions are all reported", () => {
  const r = verify(resignedEnvelope(base, (o) => {
    o.availability.available = false;
    o.price.exact = false;
  }));
  const q = quoteChecks(r);
  assert.deepEqual(
    [...q.failures].sort(),
    [QuoteFailure.AVAILABILITY_NOT_TRUE, QuoteFailure.PRICE_NOT_EXACT].sort(),
  );
});
