// Verdict statuses and reason codes for VRP signed-offer verification.
//
// The single safety rule an agent must honour: only a `verified` result may be
// quoted as an official direct offer. Every other status — expired, invalid,
// unverifiable — MUST block quoting. This is fail-closed by construction.

/**
 * Offer-level verdicts. Exactly one is returned per verification.
 *
 *  - verified     signature valid AND the offer's lifetime meets spec §5 and §6
 *                 (generated_at and valid_until well-formed, a positive lifetime
 *                 of at most 900 seconds, generated_at at most 60 seconds ahead
 *                 of the clock) AND the offer is still fresh (valid_until > now)
 *  - expired      signature valid and lifetime well-formed, BUT valid_until has
 *                 passed
 *  - invalid      the presented ARTIFACT fails verification: a signature is
 *                 present and does not verify, the envelope is
 *                 tampered/malformed, or the signed lifetime breaks a rule a
 *                 node MUST keep (§5: valid_until not later than generated_at,
 *                 or more than 900 seconds after it; §6: generated_at more than
 *                 60 seconds ahead of the clock). This is a statement about the
 *                 envelope, never a negation of the underlying stay facts — per
 *                 spec §9 a failed check leaves every value inside Unknown, and
 *                 none of them may be cited as true OR false.
 *  - unverifiable we lack what we need to reach a verdict: the signing key is
 *                 absent or unusable, or generated_at / valid_until is missing
 *                 or malformed so the lifetime cannot be determined, or the
 *                 evaluation instant itself is unusable. We NEVER report
 *                 `invalid` here: absence of a key is not proof of forgery.
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
 * package's own tests exercise all seven. The rest are offer-level codes
 * raised by `verifyOffer()` only. The lifetime codes (0.3.0) use the
 * vocabulary of the VRP offer-rules vectors (examples/conformance/offer-rules/);
 * `valid_until_unusable` is this package's older name for the vectors'
 * `malformed_valid_until` and is kept.
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
  // Offer-level lifetime (0.3.0; spec §5, §6)
  GENERATED_AT_UNUSABLE: "generated_at_unusable",
  LIFETIME_NOT_POSITIVE: "lifetime_not_positive",
  LIFETIME_TOO_LONG: "lifetime_too_long",
  GENERATED_AT_IN_FUTURE: "generated_at_in_future",
  CLOCK_UNUSABLE: "clock_unusable",
  // Offer-level version (1.0 candidate; spec §5, §9): the signed payload
  // declares "1.0" or "0.1". Same codes as the vrp-spec offer vectors.
  UNSUPPORTED_VERSION: "unsupported_version",
  MISSING_PROTOCOL_VERSION: "missing_protocol_version",
});
