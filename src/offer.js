// Offer-level verification for VRP signed verified-stay offers.
//
// This layers a typed verdict (Status) and a freshness check on top of the
// pure JWS verification in jws.js. The trust root is the host domain's own
// JWKS document — there is no central registry, and this package never
// contacts one.

import { verifyCompactJws } from "./jws.js";
import { Status, Reason } from "./status.js";

/** Deterministic JSON with sorted keys, for envelope/payload comparison. */
function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(",")}}`;
}

/** Parse a Date or ISO-8601 string to epoch ms, or NaN. */
function toInstant(v) {
  if (v instanceof Date) return v.getTime();
  const t = Date.parse(String(v));
  return Number.isFinite(t) ? t : NaN;
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

const HUMAN = {
  [Reason.MALFORMED_JWS]: "the compact JWS is not a well-formed header.payload.signature",
  [Reason.MALFORMED_HEADER]: "the JWS protected header is not valid JSON",
  [Reason.UNEXPECTED_ALG]: "the JWS declares an algorithm other than EdDSA (downgrade)",
  [Reason.KID_NOT_IN_JWKS]: "the header kid is not present in the JWKS document",
  [Reason.UNSUPPORTED_KEY]: "the resolved key is not an Ed25519 OKP key",
  [Reason.SIGNATURE_MISMATCH]: "the signature does not verify against the resolved key",
  [Reason.MALFORMED_PAYLOAD]: "the signed payload is not valid JSON",
  [Reason.NO_JWS]: "no compact JWS was found on the envelope",
  [Reason.PAYLOAD_OFFER_MISMATCH]: "the signed payload does not match the enclosed offer",
  [Reason.VALID_UNTIL_UNUSABLE]:
    "valid_until is missing or malformed, so freshness cannot be determined",
};

/**
 * @typedef {object} OfferVerificationResult
 * @property {"verified"|"expired"|"invalid"|"unverifiable"} status
 * @property {string|null} code    a Reason code, or null when verified
 * @property {string} reason       a short human-readable explanation
 * @property {boolean|null} fresh  offer.valid_until > now; null unless the
 *                                 signature verified
 * @property {object|null} header  the JWS protected header, when available
 * @property {object|null} payload the signed offer payload, when available
 * @property {boolean|null} payloadMatchesOffer  whether envelope.offer equals
 *                                 the signed payload; null if not checkable
 */

/**
 * Verify a signed VRP verified-stay-offer against a host-domain JWKS document.
 *
 * @param {object} params
 * @param {object} [params.envelope] a `signed_verified_stay_offer` (spec §5)
 * @param {string} [params.jws]      a compact JWS, if not passing an envelope
 * @param {{ keys?: Array<object> }} params.jwks  the host-domain JWKS document
 * @param {Date|string} [params.now] evaluation instant (default: now)
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

  const validUntil = toInstant(payload?.valid_until);
  const nowMs = toInstant(now);
  if (!Number.isFinite(validUntil) || !Number.isFinite(nowMs)) {
    // §6 makes a missing/malformed valid_until non-quoteable, and §9 classes
    // it as Unknown — undeterminable freshness is `unverifiable`, not a claim
    // that the offer expired.
    return result(
      Status.UNVERIFIABLE,
      Reason.VALID_UNTIL_UNUSABLE,
      null,
      res.header,
      payload,
      payloadMatchesOffer,
    );
  }
  const fresh = validUntil > nowMs;

  return result(
    fresh ? Status.VERIFIED : Status.EXPIRED,
    null,
    fresh,
    res.header,
    payload,
    payloadMatchesOffer,
  );
}

function result(status, code, fresh, header, payload, payloadMatchesOffer) {
  return {
    status,
    code,
    reason: code === null
      ? (fresh ? "signature valid and offer fresh" : "signature valid but offer expired")
      : (HUMAN[code] || code),
    fresh,
    header,
    payload,
    payloadMatchesOffer,
  };
}
