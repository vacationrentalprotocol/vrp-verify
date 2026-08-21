// Safe-to-Quote gate (VRP spec §7) — the offline-checkable portion.
//
// Spec §7 lists eleven conditions. Eight are checkable from the signed offer
// and the caller-supplied JWKS, and this module checks all eight:
//   - the JWKS contains an Ed25519 key matching the JWS   (via verifyOffer)
//   - the compact JWS verifies against that JWKS           (via verifyOffer)
//   - the signed payload matches the returned offer        (via verifyOffer,
//     when an envelope with a plaintext offer is supplied; with a bare JWS
//     the signed payload is itself the offer, so there is nothing to compare)
//   - `valid_until` is present and fresh                   (via verifyOffer)
//   - `availability.available` is true
//   - `price.exact` is true
//   - a direct booking URL is present — and per §4 it MUST be an absolute
//     https URL whose host is the offer's `canonical_domain` or a subdomain
//     of it; anything else is treated as unknown and fails the gate
//   - `agent_permission.may_quote_as_official_direct_offer` is true
//
// The remaining three §7 conditions concern the DISCOVERY DOCUMENT (fetched
// from the host-owned domain, declaring `protocol` and `protocol_version`).
// They require network context this package deliberately does not have and
// remain the CALLER'S RESPONSIBILITY. See README "What this package checks".

import { Status } from "./status.js";

/** Named codes for failed quote-gate conditions. */
export const QuoteFailure = Object.freeze({
  NOT_VERIFIED: "not_verified",
  AVAILABILITY_NOT_TRUE: "availability_not_true",
  PRICE_NOT_EXACT: "price_not_exact",
  BOOKING_URL_MISSING: "booking_url_missing",
  BOOKING_URL_INVALID: "booking_url_invalid",
  BOOKING_URL_HOST_MISMATCH: "booking_url_host_mismatch",
  QUOTE_PERMISSION_NOT_GRANTED: "quote_permission_not_granted",
});

// Normalize a domain through the URL parser (lowercases, punycodes IDN).
function normalizedHost(domain) {
  if (typeof domain !== "string" || domain.length === 0) return null;
  try {
    return new URL(`https://${domain}`).hostname;
  } catch {
    return null;
  }
}

// §4: absolute https URL whose host is canonical_domain or a subdomain of it.
// Returns a QuoteFailure code, or null when the URL passes.
function bookingUrlFailure(payload) {
  const url = payload?.booking?.direct_booking_url;
  if (typeof url !== "string" || url.length === 0) {
    return QuoteFailure.BOOKING_URL_MISSING;
  }
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return QuoteFailure.BOOKING_URL_INVALID;
  }
  if (parsed.protocol !== "https:") return QuoteFailure.BOOKING_URL_INVALID;

  const canonical = normalizedHost(payload?.canonical_domain);
  if (!canonical) return QuoteFailure.BOOKING_URL_HOST_MISMATCH; // cannot confirm -> unknown -> fail closed
  const host = parsed.hostname;
  // Deliberately stricter than §4's registrable-domain wording: we accept the
  // canonical_domain host itself or its children only. Deriving the registrable
  // domain of an arbitrary canonical_domain would require a Public Suffix List
  // (a dependency, and a fail-OPEN risk if approximated), so when
  // canonical_domain is itself a subdomain, sibling subdomains are rejected.
  // This errs fail-closed: it can refuse a spec-valid URL, never accept a
  // third-party host.
  if (host !== canonical && !host.endsWith(`.${canonical}`)) {
    return QuoteFailure.BOOKING_URL_HOST_MISMATCH;
  }
  return null;
}

/**
 * Evaluate the offline-checkable Safe-to-Quote conditions (§7, §4) against a
 * `verifyOffer()` result.
 *
 * @param {import("./offer.js").OfferVerificationResult} verification
 * @returns {{ ok: boolean, failures: string[] }}  `ok` is true only when every
 *          condition passes; `failures` lists QuoteFailure codes otherwise.
 */
export function quoteChecks(verification) {
  const failures = [];

  if (!verification || verification.status !== Status.VERIFIED) {
    // Covers signature, key resolution, payload/offer match, and freshness.
    return { ok: false, failures: [QuoteFailure.NOT_VERIFIED] };
  }

  const payload = verification.payload;
  if (payload?.availability?.available !== true) {
    failures.push(QuoteFailure.AVAILABILITY_NOT_TRUE);
  }
  if (payload?.price?.exact !== true) {
    failures.push(QuoteFailure.PRICE_NOT_EXACT);
  }
  const urlFailure = bookingUrlFailure(payload);
  if (urlFailure) failures.push(urlFailure);
  if (payload?.agent_permission?.may_quote_as_official_direct_offer !== true) {
    failures.push(QuoteFailure.QUOTE_PERMISSION_NOT_GRANTED);
  }

  return { ok: failures.length === 0, failures };
}

/**
 * True only when every offline-checkable Safe-to-Quote condition passes.
 * The three discovery-document conditions of §7 remain the caller's
 * responsibility. Everything short of a full pass is false — fail closed.
 */
export function safeToQuote(verification) {
  return quoteChecks(verification).ok;
}
