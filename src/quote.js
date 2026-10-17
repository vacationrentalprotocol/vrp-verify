// Safe-to-Quote gate (VRP spec §7).
//
// This module checks, from the signed offer, the caller-supplied JWKS, the
// domain the caller fetched the offer from and the two public lists:
//   - the JWKS holds the key the JWS header's kid names    (via verifyOffer)
//   - the compact JWS verifies against that JWKS           (via verifyOffer)
//   - the signed payload matches the returned offer        (via verifyOffer,
//     when an envelope with a plaintext offer is supplied; with a bare JWS
//     the signed payload is itself the offer, so there is nothing to compare)
//   - `valid_until` is present and fresh                   (via verifyOffer)
//   - the signed `canonical_domain` is the domain the offer was fetched from
//   - that domain is a host-owned domain (§2)
//   - `availability.available` is true
//   - `price.exact` is true
//   - a direct booking URL is present, and it is a node URL (§2, §5.1): https,
//     host `canonical_domain` or `www.` + it, no userinfo, default port
//   - `agent_permission.may_quote_as_official_direct_offer` is true
//
// The discovery-document conditions are checked by `discoveryChecks()`
// (src/domain.js) on the document the caller fetched. Fetching, and following
// redirects only to node URLs, remain the caller's: this package has no
// network access. See README "What this package checks".

import { Status } from "./status.js";
import { checkHostOwned, checkNodeUrl } from "./domain.js";

/** Named codes for failed quote-gate conditions. */
export const QuoteFailure = Object.freeze({
  NOT_VERIFIED: "not_verified",
  AVAILABILITY_NOT_TRUE: "availability_not_true",
  PRICE_NOT_EXACT: "price_not_exact",
  BOOKING_URL_MISSING: "booking_url_missing",
  BOOKING_URL_INVALID: "booking_url_invalid",
  BOOKING_URL_HOST_MISMATCH: "booking_url_host_mismatch",
  QUOTE_PERMISSION_NOT_GRANTED: "quote_permission_not_granted",
  FETCHED_DOMAIN_UNKNOWN: "fetched_domain_unknown",
  OFFER_DOMAIN_MISMATCH: "offer_domain_mismatch",
  HOST_OWNED_UNKNOWN: "host_owned_unknown",
  NOT_HOST_OWNED: "not_host_owned",
});

// §5.1: the direct booking URL is a node URL of the offer's canonical_domain.
// Returns a QuoteFailure code, or null when the URL passes.
function bookingUrlFailure(payload) {
  const url = payload?.booking?.direct_booking_url;
  if (typeof url !== "string" || url.length === 0) {
    return QuoteFailure.BOOKING_URL_MISSING;
  }
  const canonical = payload?.canonical_domain;
  if (typeof canonical !== "string" || canonical.length === 0) {
    return QuoteFailure.BOOKING_URL_HOST_MISMATCH; // cannot confirm -> unknown -> fail closed
  }
  const reason = checkNodeUrl(url, canonical);
  if (reason === null) return null;
  return reason === "url_host_mismatch" ? QuoteFailure.BOOKING_URL_HOST_MISMATCH : QuoteFailure.BOOKING_URL_INVALID;
}

/**
 * Evaluate the Safe-to-Quote conditions (§7) against a `verifyOffer()` result.
 *
 * @param {import("./offer.js").OfferVerificationResult} verification
 * @param {{ fetchedDomain?: string, lists?: { icannRules: string[], specification13Tlds: string[] } }} [context]
 *        `fetchedDomain` is the host of the URL the caller requested the offer
 *        from; `lists` are the ICANN section of the Public Suffix List and the
 *        Specification 13 top-level domains of ICANN's gTLD list. Without
 *        either, the offer is unknown and the gate fails closed.
 * @returns {{ ok: boolean, failures: string[] }}  `ok` is true only when every
 *          condition passes; `failures` lists QuoteFailure codes otherwise.
 */
export function quoteChecks(verification, { fetchedDomain, lists } = {}) {
  const failures = [];

  if (!verification || verification.status !== Status.VERIFIED) {
    // Covers signature, key resolution, payload/offer match, and freshness.
    return { ok: false, failures: [QuoteFailure.NOT_VERIFIED] };
  }

  const payload = verification.payload;
  // §7: the offer is the offer of the domain it was fetched from.
  if (typeof fetchedDomain !== "string" || fetchedDomain.length === 0) {
    failures.push(QuoteFailure.FETCHED_DOMAIN_UNKNOWN);
  } else if (payload?.canonical_domain !== fetchedDomain) {
    failures.push(QuoteFailure.OFFER_DOMAIN_MISMATCH);
  }
  // §2: that domain is a host-owned domain.
  const owned = checkHostOwned(payload?.canonical_domain, lists);
  if (owned === "lists_unavailable") failures.push(QuoteFailure.HOST_OWNED_UNKNOWN);
  else if (owned !== null) failures.push(QuoteFailure.NOT_HOST_OWNED);

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
 * True only when every Safe-to-Quote condition `quoteChecks()` checks passes.
 * The discovery document is checked with `discoveryChecks()`. Everything short
 * of a full pass is false — fail closed.
 */
export function safeToQuote(verification, context) {
  return quoteChecks(verification, context).ok;
}
