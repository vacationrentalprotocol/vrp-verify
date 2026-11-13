// Offer-level verification for VRP signed verified-stay offers.
//
// This layers a typed verdict (Status), the lifetime rules of spec §5 and §6
// and a freshness check on top of the pure JWS verification in jws.js. The
// trust root is the host domain's own JWKS document — there is no central
// registry, and this package never contacts one.

import { verifyCompactJws } from "./jws.js";
import { Status, Reason } from "./status.js";
import { OfferRule, lifetimeReasons, toClock } from "./offer-rules.js";

/** Deterministic JSON with sorted keys, for envelope/payload comparison. */
function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(",")}}`;
}

// Map a JWS-level reason to an offer-level status. Absence or unusability of
// the signing key is UNVERIFIABLE (we could not check), never INVALID (a claim
// that the offer is forged).
function statusForReason(reason) {
  switch (reason) {
    case Reason.KID_NOT_IN_JWKS:
    case Reason.UNSUPPORTED_KEY:
      return Status.UNVERIFIABLE;
    default:
      return Status.INVALID; // malformed_*, unexpected_alg, signature_mismatch
  }
}

// Map the first lifetime reason (spec §5, §6; the vectors' order) to a verdict.
// A missing or malformed instant leaves the lifetime undeterminable
// (UNVERIFIABLE); a lifetime a node MUST NOT sign is a defect of the artifact
// (INVALID); a lifetime that has merely run out is EXPIRED.
function verdictForLifetime(reason) {
  switch (reason) {
    case OfferRule.MALFORMED_GENERATED_AT:
      return [Status.UNVERIFIABLE, Reason.GENERATED_AT_UNUSABLE];
    case OfferRule.MALFORMED_VALID_UNTIL:
      return [Status.UNVERIFIABLE, Reason.VALID_UNTIL_UNUSABLE];
    case OfferRule.LIFETIME_NOT_POSITIVE:
      return [Status.INVALID, Reason.LIFETIME_NOT_POSITIVE];
    case OfferRule.LIFETIME_TOO_LONG:
      return [Status.INVALID, Reason.LIFETIME_TOO_LONG];
    case OfferRule.GENERATED_AT_IN_FUTURE:
      return [Status.INVALID, Reason.GENERATED_AT_IN_FUTURE];
    case OfferRule.EXPIRED:
      return [Status.EXPIRED, null];
    default:
      return [Status.VERIFIED, null];
  }
}

const HUMAN = {
  [Reason.MALFORMED_JWS]: "the compact JWS is not a well-formed header.payload.signature",
  [Reason.MALFORMED_HEADER]: "the JWS protected header is not valid JSON",
  [Reason.UNEXPECTED_ALG]: "the JWS declares an algorithm other than EdDSA (downgrade)",
  [Reason.KID_NOT_IN_JWKS]: "the header kid is not present in the JWKS document",
  [Reason.UNSUPPORTED_KEY]: "the resolved key is not an Ed25519 OKP key that names its alg EdDSA",
  [Reason.SIGNATURE_MISMATCH]: "the signature does not verify against the resolved key",
  [Reason.MALFORMED_PAYLOAD]: "the signed payload is not valid JSON",
  [Reason.NO_JWS]: "no compact JWS was found on the envelope",
  [Reason.PAYLOAD_OFFER_MISMATCH]: "the signed payload does not match the enclosed offer",
  [Reason.VALID_UNTIL_UNUSABLE]:
    "valid_until is missing or not a UTC date-time ending in Z, so the lifetime cannot be determined (§5, §6)",
  [Reason.GENERATED_AT_UNUSABLE]:
    "generated_at is missing or not a UTC date-time ending in Z, so the lifetime cannot be determined (§5, §6)",
  [Reason.LIFETIME_NOT_POSITIVE]: "valid_until is not later than generated_at (§5)",
  [Reason.LIFETIME_TOO_LONG]: "valid_until is more than 900 seconds after generated_at (§5)",
  [Reason.GENERATED_AT_IN_FUTURE]: "generated_at is more than 60 seconds later than the evaluation instant (§6)",
  [Reason.CLOCK_UNUSABLE]: "the evaluation instant `now` is not a usable date, so freshness cannot be determined",
};

/**
 * @typedef {object} OfferVerificationResult
 * @property {"verified"|"expired"|"invalid"|"unverifiable"} status
 * @property {string|null} code    a Reason code, or null when verified or expired
 * @property {string} reason       a short human-readable explanation
 * @property {boolean|null} fresh  offer.valid_until > now; null unless the
 *                                 verdict is verified or expired
 * @property {object|null} header  the JWS protected header, when available
 * @property {object|null} payload the signed offer payload, when available
 * @property {boolean|null} payloadMatchesOffer  whether envelope.offer equals
 *                                 the signed payload; null if not checkable
 * @property {string|null} evaluatedAt  the instant `now` the lifetime was
 *                                 judged at, as an ISO date-time; null when the
 *                                 verdict was reached before the clock mattered
 * @property {string[]} reasons    every lifetime rule the signed payload breaks
 *                                 at `now` (spec §5, §6), in the order of the
 *                                 VRP offer-rules vectors; empty when none, or
 *                                 when the signature did not verify
 */

/**
 * Verify a signed VRP verified-stay-offer against a host-domain JWKS document.
 *
 * @param {object} params
 * @param {object} [params.envelope] a `signed_verified_stay_offer` (spec §5)
 * @param {string} [params.jws]      a compact JWS, if not passing an envelope
 * @param {{ keys?: Array<object> }} params.jwks  the host-domain JWKS document
 * @param {Date|string|number} [params.now] evaluation instant (default: now)
 * @returns {OfferVerificationResult}
 */
export function verifyOffer({ envelope, jws, jwks, now = new Date() } = {}) {
  const compact = typeof jws === "string" ? jws : envelope?.signature?.jws;
  if (typeof compact !== "string" || compact.length === 0) {
    return result(Status.INVALID, Reason.NO_JWS, null, null, null, null);
  }

  const res = verifyCompactJws(compact, jwks || {});
  if (!res.valid) {
    return result(statusForReason(res.reason), res.reason, null, res.header ?? null, null, null);
  }

  const payload = res.payload;

  // The signature is valid over the signed bytes. If a plaintext envelope.offer
  // is also present, it must equal the signed payload — otherwise an attacker
  // swapped the visible offer while keeping a valid signature over other bytes.
  let payloadMatchesOffer = null;
  if (envelope && typeof envelope === "object" && "offer" in envelope) {
    payloadMatchesOffer = stableStringify(envelope.offer) === stableStringify(payload);
    if (!payloadMatchesOffer) {
      return result(
        Status.INVALID, Reason.PAYLOAD_OFFER_MISMATCH, null, res.header, payload, false,
      );
    }
  }

  const clock = toClock(now);
  if (!Number.isFinite(clock)) {
    return result(Status.UNVERIFIABLE, Reason.CLOCK_UNUSABLE, null, res.header, payload, payloadMatchesOffer);
  }
  const evaluatedAt = new Date(clock).toISOString();

  // Spec §5, §6: generated_at and valid_until, read from the SIGNED payload
  // only, must be UTC date-times ending in Z that exist, the lifetime must be
  // positive and at most 900 seconds, generated_at at most 60 seconds ahead of
  // the clock, and valid_until must not have passed. Each failure leaves the
  // offer non-quoteable (§6) and Unknown (§9).
  const reasons = lifetimeReasons(payload, clock);
  const [status, code] = verdictForLifetime(reasons[0]);
  const fresh = status === Status.VERIFIED ? true : status === Status.EXPIRED ? false : null;

  return result(status, code, fresh, res.header, payload, payloadMatchesOffer, evaluatedAt, reasons);
}

function result(status, code, fresh, header, payload, payloadMatchesOffer, evaluatedAt = null, reasons = []) {
  return {
    status,
    code,
    reason: code === null
      ? (fresh ? "signature valid, lifetime within spec §5 and §6, offer fresh" : "signature valid but offer expired")
      : (HUMAN[code] || code),
    fresh,
    header,
    payload,
    payloadMatchesOffer,
    evaluatedAt,
    reasons,
  };
}
