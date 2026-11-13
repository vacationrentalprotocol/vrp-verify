// Byte-for-byte conformance: run THIS package's verifyCompactJws against the
// committed VRP signed-offer vectors and assert its outcome matches each
// vector's declared `expected` block — using the exact comparison the vrp-spec
// reference runner (scripts/verify-offer-vectors.mjs) performs.
//
// Vectors 01–05 are VRP v0.1's. Vectors 06–15 are the VRP 1.0 candidate's
// (vrp-spec pull request 187, copied byte for byte): the two names of the
// signing operation, and the version the signed offer declares. For those the
// reference runner applies the version rule to the signed payload after the
// signature verifies; this test composes the same two steps.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyCompactJws, checkOfferVersion } from "../index.js";

const vectorsDir = join(dirname(fileURLToPath(import.meta.url)), "vectors");
const files = readdirSync(vectorsDir).filter((f) => f.endsWith(".json")).sort();

test("vector set is non-empty", () => {
  assert.ok(files.length >= 15, `expected >= 15 vectors, found ${files.length}`);
});

for (const file of files) {
  const v = JSON.parse(readFileSync(join(vectorsDir, file), "utf8"));

  test(`${file}: self-describing shape`, () => {
    for (const field of ["name", "description", "clock", "jwks", "input", "expected"]) {
      assert.notEqual(v[field], undefined, `missing ${field}`);
    }
  });

  test(`${file}: matches expected (${v.name})`, () => {
    const jws = v.input?.signature?.jws;
    const result = verifyCompactJws(jws, v.jwks);

    const versionReason = result.valid === true ? checkOfferVersion(result.payload) : null;
    const verified = result.valid === true && versionReason === null;
    const reason = result.reason ?? versionReason;
    let fresh = null;
    if (verified) {
      const validUntil = Date.parse(result.payload?.valid_until ?? "");
      fresh = Number.isFinite(validUntil) && validUntil > Date.parse(v.clock);
    }

    assert.equal(verified, v.expected.verified, "verified");
    assert.equal(reason, v.expected.reason, "reason");
    assert.equal(fresh, v.expected.fresh, "fresh");
  });
}
