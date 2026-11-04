// Safe-to-Quote gate (VRP spec §7) — the offline-checkable portion.
//
// Spec §7 lists eleven conditions. This module checks the eight that are
// checkable from the signed offer and the caller-supplied JWKS, and — from
// 0.2.0 — the host-owned domain (§2) and the offer's binding to the domain it
// was fetched from (§7), from the domain and the two lists the caller passes:
//   - the JWKS contains an Ed25519 key matching the JWS   (via verifyOffer)
//   - the compact JWS verifies against that JWKS           (via verifyOffer)
//   - the signed payload matches the returned offer        (via verifyOffer,
//     when an envelope with a plaintext offer is supplied; with a bare JWS
//     the signed payload is itself the offer, so there is nothing to compare)
//   - `valid_until` is present and fresh                   (via verifyOffer)
//   - `availability.available` is true
//   - `price.exact` is true
//   - a direct booking URL is present — and per §5.1 it MUST be a node URL
//     (§2): https, host the offer's `canonical_domain` or `www.` followed by
//     it, no userinfo, the default port; anything else is treated as unknown
//     and fails the gate
//   - `agent_permission.may_quote_as_official_direct_offer` is true
//   - the signed `canonical_domain` is the domain the offer was fetched from
//     (§7), and that domain is host-owned (§2): its own registrable domain
//     under the ICANN section of the Public Suffix List, not under a brand or
//     closed top-level domain. No domain, or no usable lists, is unknown
//     (§2, §9) and fails the gate.
//
// What remains the CALLER'S RESPONSIBILITY needs network context this package
// deliberately does not have: fetching (over HTTPS, following only redirects
// to node URLs, §2) and the discovery document itself (its `canonical_domain`
// is the fetched domain, and it declares `protocol` and `protocol_version`).
// See README "What this package checks".

import { Status } from "./status.js";
import { checkHostOwned, fetchedHost, isHostOwnedLists } from "./host-domain.js";

/** Named codes for failed quote-gate conditions. */
export const QuoteFailure = Object.freeze({
  NOT_VERIFIED: "not_verified",
  AVAILABILITY_NOT_TRUE: "availability_not_true",
  PRICE_NOT_EXACT: "price_not_exact",
  BOOKING_URL_MISSING: "booking_url_missing",
  BOOKING_URL_INVALID: "booking_url_invalid",
  BOOKING_URL_HOST_MISMATCH: "booking_url_host_mismatch",
  QUOTE_PERMISSION_NOT_GRANTED: "quote_permission_not_granted",
  // §2, §7 (0.2.0): the caller did not say which domain the offer was fetched
  // from, so the offer cannot be bound to a host-owned domain — unknown.
  DOMAIN_UNKNOWN: "domain_unknown",
  // §2, §9: no usable copy of the ICANN section of the Public Suffix List or
  // of ICANN's gTLD list was passed — the node is unknown.
  HOST_OWNED_UNKNOWN: "host_owned_unknown",
  // §7: the signed `canonical_domain` is not the domain it was fetched from.
  OFFER_DOMAIN_MISMATCH: "offer_domain_mismatch",
  // §2: `canonical_domain` is not a host-owned domain. Same codes as the
  // vrp-spec host-domain conformance vectors.
  MALFORMED_DOMAIN: "malformed_domain",
  PUBLIC_SUFFIX: "public_suffix",
  NOT_HOST_OWNED: "not_host_owned",
  CLOSED_TLD: "closed_tld",
});

// §2 host-owned domain and §7 offer binding. Returns QuoteFailure codes.
function hostDomainFailures(payload, context) {
  const fetched = fetchedHost(context?.domain);
  if (fetched === null) return [QuoteFailure.DOMAIN_UNKNOWN];
  const failures = [];
  const canonical = payload?.canonical_domain;
  if (canonical !== fetched) failures.push(QuoteFailure.OFFER_DOMAIN_MISMATCH);
  if (!isHostOwnedLists(context?.hostOwnedLists)) {
    failures.push(QuoteFailure.HOST_OWNED_UNKNOWN);
    return failures;
  }
  const reason = checkHostOwned(canonical, context.hostOwnedLists);
  if (reason) failures.push(reason);
  return failures;
}

// Normalize a domain through the URL parser (lowercases, punycodes IDN).
function normalizedHost(domain) {
  if (typeof domain !== "string" || domain.length === 0) return null;
  try {
    return new URL(`https://${domain}`).hostname;
  } catch {
    return null;
  }
}

// §5.1: a node URL (§2) of the offer's canonical_domain. Returns a
// QuoteFailure code, or null when the URL passes.
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
  if (parsed.username || parsed.password || parsed.port) {
    return QuoteFailure.BOOKING_URL_INVALID;
  }

  const canonical = normalizedHost(payload?.canonical_domain);
  if (!canonical) return QuoteFailure.BOOKING_URL_HOST_MISMATCH; // cannot confirm -> unknown -> fail closed
  const host = parsed.hostname;
  // canonical_domain or www. + canonical_domain, and no other name: another
  // name under the domain (airbnb.example) may be served by another party.
  if (host !== canonical && host !== `www.${canonical}`) {
    return QuoteFailure.BOOKING_URL_HOST_MISMATCH;
  }
  return null;
}

/**
 * Evaluate the offline-checkable Safe-to-Quote conditions (§7, §5.1, §2)
 * against a `verifyOffer()` result.
 *
 * @param {import("./offer.js").OfferVerificationResult} verification
 * @param {{ domain?: string, hostOwnedLists?: { icannRules: string[], specification13Tlds: string[] } }} [context]
 *        `domain`: the domain being verified — the host of the URL the offer
 *        (and its discovery document) was requested from, before any
 *        redirect. `hostOwnedLists`: the ICANN section of the Public Suffix
 *        List and the Specification 13 top-level domains (see
 *        icannRulesFromPsl, specification13FromGtlds). Without either, the
 *        gate fails closed.
 * @returns {{ ok: boolean, failures: string[] }}  `ok` is true only when every
 *          condition passes; `failures` lists QuoteFailure codes otherwise.
 */
export function quoteChecks(verification, context) {
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
  failures.push(...hostDomainFailures(payload, context));

  return { ok: failures.length === 0, failures };
}

/**
 * True only when every offline-checkable Safe-to-Quote condition passes,
 * including the host-owned domain (§2) and the offer's binding to the domain
 * it was fetched from (§7). Without `context.domain` and
 * `context.hostOwnedLists` it is false. Fetching and the discovery document
 * remain the caller's responsibility. Everything short of a full pass is
 * false — fail closed.
 *
 * @param {import("./offer.js").OfferVerificationResult} verification
 * @param {{ domain?: string, hostOwnedLists?: { icannRules: string[], specification13Tlds: string[] } }} [context]
 */
export function safeToQuote(verification, context) {
  return quoteChecks(verification, context).ok;
}
