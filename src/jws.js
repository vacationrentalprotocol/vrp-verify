// Compact-JWS verification for VRP, using only the Node standard library.
//
// This is a pure Ed25519 (EdDSA) signature check over the exact received
// `header.payload` bytes. There is deliberately:
//   - no canonicalization    (the signature is verified over the bytes as sent)
//   - no network access       (the caller supplies the JWKS document)
//   - no clock                (freshness is an offer-level concern; see offer.js)
//   - no third-party crypto   (node:crypto Ed25519 only)
//
// The algorithm is pinned to EdDSA: a JWS declaring any other `alg` is rejected
// as a downgrade attempt rather than trusted.
//
// Reason codes use the same vocabulary as the reference verifier behind the
// published VRP conformance vectors (examples/conformance/offer/ in the
// vrp-spec repository), and this verifier's outcome matches every committed
// vector's expected block (verified/reason/fresh) — see the conformance-parity
// tests. Where this implementation is more defensive than the reference (it
// tolerates a null/shapeless JWKS document and catches a throwing crypto
// verify), the extra paths still return codes from the same vocabulary.

import { createPublicKey, verify } from "node:crypto";
import { Reason } from "./status.js";

function b64urlToBuf(s) {
  return Buffer.from(String(s), "base64url");
}

/**
 * Verify a compact JWS against a JWKS document, resolving the verification key
 * by the protected-header `kid`.
 *
 * @param {string} compactJws  a `header.payload.signature` compact JWS
 * @param {{ keys?: Array<object> }} jwksDoc  a JWKS document
 * @returns {{ valid: boolean, reason: string|null, header?: object, payload?: object }}
 *          On success: `{ valid: true, reason: null, header, payload }`.
 *          On failure: `{ valid: false, reason, header? }` where `reason` is a
 *          code from `Reason`.
 */
export function verifyCompactJws(compactJws, jwksDoc) {
  const parts = String(compactJws).split(".");
  if (parts.length !== 3) return { valid: false, reason: Reason.MALFORMED_JWS };
  const [b64h, b64p, b64s] = parts;

  let header;
  try {
    header = JSON.parse(b64urlToBuf(b64h).toString("utf8"));
  } catch {
    return { valid: false, reason: Reason.MALFORMED_HEADER };
  }
  if (header.alg !== "EdDSA") {
    return { valid: false, reason: Reason.UNEXPECTED_ALG, header };
  }

  const keys = (jwksDoc && Array.isArray(jwksDoc.keys)) ? jwksDoc.keys : [];
  const jwk = keys.find((k) => k && k.kid === header.kid);
  if (!jwk) return { valid: false, reason: Reason.KID_NOT_IN_JWKS, header };
  if (jwk.crv !== "Ed25519" || jwk.kty !== "OKP") {
    return { valid: false, reason: Reason.UNSUPPORTED_KEY, header };
  }

  let key;
  try {
    key = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, format: "jwk" });
  } catch {
    return { valid: false, reason: Reason.UNSUPPORTED_KEY, header };
  }

  let ok;
  try {
    ok = verify(null, Buffer.from(`${b64h}.${b64p}`), key, b64urlToBuf(b64s));
  } catch {
    // A structurally impossible signature (e.g. wrong length) is a mismatch,
    // never a thrown error to the caller.
    return { valid: false, reason: Reason.SIGNATURE_MISMATCH, header };
  }
  if (!ok) return { valid: false, reason: Reason.SIGNATURE_MISMATCH, header };

  let payload;
  try {
    payload = JSON.parse(b64urlToBuf(b64p).toString("utf8"));
  } catch {
    return { valid: false, reason: Reason.MALFORMED_PAYLOAD, header };
  }
  return { valid: true, reason: null, header, payload };
}
