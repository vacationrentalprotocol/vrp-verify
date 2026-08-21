// Exercise EVERY JWS-level reason code, not only the subset the committed
// vectors cover (the vectors exercise null, signature_mismatch, and
// kid_not_in_jwks). This upgrades the "same code vocabulary" claim from
// asserted to demonstrated for all seven codes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyCompactJws, verifyOffer, Reason, Status } from "../index.js";
import { KID, b64url, signRawSegments, resignedEnvelope } from "./helpers.mjs";

const vectorsDir = join(dirname(fileURLToPath(import.meta.url)), "vectors");
const base = JSON.parse(readFileSync(join(vectorsDir, "01-valid-fresh.json"), "utf8"));
const jwks = base.jwks;
const goodJws = base.input.signature.jws;

const reasonOf = (jws, doc = jwks) => verifyCompactJws(jws, doc).reason;

test("malformed_jws: not three dot-separated segments", () => {
  assert.equal(reasonOf("only.two"), Reason.MALFORMED_JWS);
  assert.equal(reasonOf("a.b.c.d"), Reason.MALFORMED_JWS);
});

test("malformed_header: header segment is not valid JSON", () => {
  const [, p, s] = goodJws.split(".");
  const jws = `${b64url("not json at all")}.${p}.${s}`;
  assert.equal(reasonOf(jws), Reason.MALFORMED_HEADER);
});

test("unexpected_alg: any alg other than EdDSA is a rejected downgrade", () => {
  for (const alg of ["none", "RS256", "HS256", "ES256"]) {
    const header = b64url(JSON.stringify({ alg, typ: "JWT", kid: KID }));
    const [, p, s] = goodJws.split(".");
    assert.equal(reasonOf(`${header}.${p}.${s}`), Reason.UNEXPECTED_ALG, alg);
  }
});

test("unsupported_key: kid resolves to a non-Ed25519 key", () => {
  const rsaJwks = { keys: [{ kty: "RSA", kid: KID, n: "AQAB", e: "AQAB" }] };
  assert.equal(reasonOf(goodJws, rsaJwks), Reason.UNSUPPORTED_KEY);
  const p256Jwks = { keys: [{ kty: "EC", crv: "P-256", kid: KID, x: "AA", y: "AA" }] };
  assert.equal(reasonOf(goodJws, p256Jwks), Reason.UNSUPPORTED_KEY);
});

test("malformed_payload: valid signature over a non-JSON payload", () => {
  const header = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: KID }));
  const jws = signRawSegments(header, b64url("this is not json"));
  const r = verifyCompactJws(jws, jwks);
  assert.equal(r.valid, false);
  assert.equal(r.reason, Reason.MALFORMED_PAYLOAD);
});

test("shapeless JWKS documents degrade to kid_not_in_jwks, never a throw", () => {
  for (const doc of [null, undefined, {}, { keys: "nope" }, { keys: [null] }]) {
    // call directly — reasonOf's default parameter would swallow `undefined`
    const r = verifyCompactJws(goodJws, doc);
    assert.equal(r.valid, false, String(doc));
    assert.equal(r.reason, Reason.KID_NOT_IN_JWKS, String(doc));
  }
});

// --- offer-level codes not covered by the vectors ---

test("payload_offer_mismatch: plaintext offer swapped after signing", () => {
  const envelope = structuredClone(base.input);
  envelope.offer.price.public_total = 1; // mutate the PLAINTEXT offer only
  const r = verifyOffer({ envelope, jwks, now: base.clock });
  assert.equal(r.status, Status.INVALID);
  assert.equal(r.code, Reason.PAYLOAD_OFFER_MISMATCH);
  assert.equal(r.payloadMatchesOffer, false);
});

test("valid_until missing: unverifiable with valid_until_unusable, not expired", () => {
  const env = resignedEnvelope(base, (o) => { delete o.valid_until; });
  const r = verifyOffer({ envelope: env, jwks, now: base.clock });
  assert.equal(r.status, Status.UNVERIFIABLE);
  assert.equal(r.code, Reason.VALID_UNTIL_UNUSABLE);
  assert.equal(r.fresh, null);
});

test("valid_until malformed: unverifiable with valid_until_unusable", () => {
  const env = resignedEnvelope(base, (o) => { o.valid_until = "not-a-date"; });
  const r = verifyOffer({ envelope: env, jwks, now: base.clock });
  assert.equal(r.status, Status.UNVERIFIABLE);
  assert.equal(r.code, Reason.VALID_UNTIL_UNUSABLE);
});

test("genuinely expired stays expired (vector 02 unchanged)", () => {
  const v02 = JSON.parse(readFileSync(join(vectorsDir, "02-valid-expired.json"), "utf8"));
  const r = verifyOffer({ envelope: v02.input, jwks: v02.jwks, now: v02.clock });
  assert.equal(r.status, Status.EXPIRED);
  assert.equal(r.code, null);
  assert.equal(r.fresh, false);
});
