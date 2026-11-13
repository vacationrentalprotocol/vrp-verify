// @vacationrentalprotocol/vrp-verify
//
// Zero-dependency reference verifier for VRP (Vacation Rental Protocol) signed
// verified-stay offers. Pure Ed25519 (EdDSA) verification of a host-domain
// signed offer against the host's own JWKS document — no network, no registry,
// no third-party crypto.

export { verifyCompactJws } from "./src/jws.js";
export { verifyOffer } from "./src/offer.js";
export { safeToQuote, quoteChecks, QuoteFailure } from "./src/quote.js";
export {
  checkOfferRules,
  OfferRule,
  MAX_LIFETIME_SECONDS,
  CLOCK_SKEW_SECONDS,
  LANGUAGE_TAG,
} from "./src/offer-rules.js";
export {
  checkHostOwned,
  registrableDomain,
  icannRulesFromPsl,
  specification13FromGtlds,
  HostDomainReason,
  CLOSED_TLDS,
  PSL_URL,
  GTLDS_URL,
} from "./src/host-domain.js";
export { Status, Reason } from "./src/status.js";
export {
  checkDiscoveryVersion,
  checkOfferVersion,
  checkDeclaredVersion,
  VersionReason,
  KNOWN_PROTOCOL_VERSIONS,
  SIGNATURE_ALGS,
  VRP_PROTOCOL,
} from "./src/version.js";
