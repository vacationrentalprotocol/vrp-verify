// Parity with the host-domain conformance vectors of vrp-spec
// (examples/conformance/host-domain/vectors.v0.1.json, ADR 0009): this
// package's domain checks give the reason every vector expects. The copy in
// test/vectors/host-domain/ is taken from vrp-spec unchanged.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CLOSED_TLDS,
  QuoteFailure,
  checkHostOwned,
  checkNodeUrl,
  checkRedirects,
  discoveryChecks,
  quoteChecks,
  verifyOffer,
} from "../index.js";

const file = join(dirname(fileURLToPath(import.meta.url)), "vectors/host-domain/vectors.v0.1.json");
const doc = JSON.parse(readFileSync(file, "utf8"));
const lists = { icannRules: doc.psl_icann_rules, specification13Tlds: doc.icann_specification13_tlds };

test("the vectors name the same closed top-level domains as this package", () => {
  assert.deepEqual(doc.closed_tlds, [...CLOSED_TLDS]);
});

for (const group of ["host_owned", "real_world"]) {
  for (const v of doc[group]) {
    test(`${group} ${v.canonical_domain}`, () => {
      assert.equal(checkHostOwned(v.canonical_domain, lists), v.expected.reason);
    });
  }
}

for (const v of doc.node_url) {
  test(`node_url ${v.field} ${v.url}`, () => {
    assert.equal(checkNodeUrl(v.url, v.canonical_domain), v.expected.reason);
  });
}

for (const v of doc.redirects) {
  test(`redirects ${v.name}`, () => {
    assert.equal(checkRedirects(v.chain, v.canonical_domain), v.expected.reason);
  });
}

// offer_binding: the discovery document names the fetched domain, and so does
// the signed offer. The booking-URL, availability and other gate conditions
// are not what these vectors test, so only the binding codes are compared.
for (const v of doc.offer_binding) {
  test(`offer_binding ${v.name}`, () => {
    const discovery = discoveryChecks(v.discovery, { fetchedDomain: v.fetched_domain });
    if (v.expected.reason === "discovery_domain_mismatch") {
      assert.ok(discovery.includes("discovery_domain_mismatch"));
      return;
    }
    assert.ok(!discovery.includes("discovery_domain_mismatch"));
    const r = verifyOffer({ envelope: v.input, jwks: v.jwks, now: v.input.offer.generated_at });
    assert.equal(r.status === "verified", v.expected.signature_valid);
    const failures = quoteChecks(r, { fetchedDomain: v.fetched_domain, lists }).failures;
    assert.equal(
      failures.includes(QuoteFailure.OFFER_DOMAIN_MISMATCH),
      v.expected.reason === "offer_domain_mismatch",
      JSON.stringify(failures),
    );
  });
}
