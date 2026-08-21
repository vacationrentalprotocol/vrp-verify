// Typed offer verdicts: run verifyOffer() against the committed vectors, using
// each vector's own clock, and assert the mapped status and the safe-to-quote
// rule. Only the fresh, correctly-signed vector may be quoted.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyOffer, safeToQuote, Status } from "../index.js";

const vectorsDir = join(dirname(fileURLToPath(import.meta.url)), "vectors");
const load = (f) => JSON.parse(readFileSync(join(vectorsDir, f), "utf8"));

// Expected offer-level status per vector (derived from each vector's expected
// block: 01 verified+fresh, 02 verified+stale, 03/05 signature_mismatch,
// 04 kid_not_in_jwks -> unverifiable, never invalid).
const EXPECT = {
  "01-valid-fresh.json": Status.VERIFIED,
  "02-valid-expired.json": Status.EXPIRED,
  "03-tampered-signature.json": Status.INVALID,
  "04-unknown-kid.json": Status.UNVERIFIABLE,
  "05-wrong-key.json": Status.INVALID,
};

for (const [file, expected] of Object.entries(EXPECT)) {
  test(`${file}: status is ${expected}`, () => {
    const v = load(file);
    const r = verifyOffer({ envelope: v.input, jwks: v.jwks, now: v.clock });
    assert.equal(r.status, expected, `${r.status} (${r.code}): ${r.reason}`);
    assert.equal(safeToQuote(r), expected === Status.VERIFIED);
  });
}

test("key absence is unverifiable, never invalid", () => {
  const v = load("04-unknown-kid.json");
  const r = verifyOffer({ envelope: v.input, jwks: v.jwks, now: v.clock });
  assert.equal(r.status, Status.UNVERIFIABLE);
  assert.notEqual(r.status, Status.INVALID);
});

test("verified offer round-trips its signed payload", () => {
  const v = load("01-valid-fresh.json");
  const r = verifyOffer({ envelope: v.input, jwks: v.jwks, now: v.clock });
  assert.equal(r.status, Status.VERIFIED);
  assert.equal(r.payloadMatchesOffer, true);
  assert.equal(r.payload.canonical_domain, "example-host.invalid");
});

test("accepts a bare jws without an envelope", () => {
  const v = load("01-valid-fresh.json");
  const r = verifyOffer({ jws: v.input.signature.jws, jwks: v.jwks, now: v.clock });
  assert.equal(r.status, Status.VERIFIED);
  assert.equal(r.payloadMatchesOffer, null); // no envelope.offer to compare
});

test("missing jws is invalid with no_jws", () => {
  const v = load("01-valid-fresh.json");
  const r = verifyOffer({ jwks: v.jwks, now: v.clock });
  assert.equal(r.status, Status.INVALID);
  assert.equal(r.code, "no_jws");
});
