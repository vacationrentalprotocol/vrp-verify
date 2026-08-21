// Verdict statuses and reason codes for VRP signed-offer verification.
//
// The single safety rule an agent must honour: only a `verified` result may be
// quoted as an official direct offer. Every other status — expired, invalid,
// unverifiable — MUST block quoting. This is fail-closed by construction.

/**
 * Offer-level verdicts. Exactly one is returned per verification.
 *
 *  - verified     signature valid AND the offer is still fresh (valid_until > now)
 *  - expired      signature valid BUT valid_until has passed
 *  - invalid      the presented ARTIFACT fails verification: a signature is
 *                 present and does not verify, or the envelope is
 *                 tampered/malformed. This is a statement about the envelope,
 *                 never a negation of the underlying stay facts — per spec §9
 *                 a failed signature check leaves every value inside Unknown,
 *                 and none of them may be cited as true OR false.
 *  - unverifiable we lack what we need to reach a verdict: the signing key is
 *                 absent or unusable, or valid_until is missing/malformed so
 *                 freshness cannot be determined. We NEVER report `invalid`
 *                 here: absence of a key is not proof of forgery.
 *
 * Only `verified` may lead to quoting. For citation purposes (§9), everything
 * other than `verified` is Unknown: fail closed.
 */
export const Status = Object.freeze({
  VERIFIED: "verified",
  EXPIRED: "expired",
  INVALID: "invalid",
  UNVERIFIABLE: "unverifiable",
});

/**
 * Reason codes.
 *
 * The first seven are JWS-level codes returned by `verifyCompactJws()`. They
 * use the same code vocabulary as the reference verifier behind the published
 * VRP conformance vectors (examples/conformance/offer/ in the vrp-spec
 * repository); the vectors themselves exercise a subset of them, and this
 * package's own tests exercise all seven. The last three are offer-level
 * codes raised by `verifyOffer()` only.
 */
export const Reason = Object.freeze({
  // JWS-level (same vocabulary as the conformance vectors)
  MALFORMED_JWS: "malformed_jws",
  MALFORMED_HEADER: "malformed_header",
  UNEXPECTED_ALG: "unexpected_alg",
  KID_NOT_IN_JWKS: "kid_not_in_jwks",
  UNSUPPORTED_KEY: "unsupported_key",
  SIGNATURE_MISMATCH: "signature_mismatch",
  MALFORMED_PAYLOAD: "malformed_payload",
  // Offer-level (verifyOffer only)
  NO_JWS: "no_jws",
  PAYLOAD_OFFER_MISMATCH: "payload_offer_mismatch",
  VALID_UNTIL_UNUSABLE: "valid_until_unusable",
});
