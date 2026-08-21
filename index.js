// @vacationrentalprotocol/vrp-verify
//
// Zero-dependency reference verifier for VRP (Vacation Rental Protocol) signed
// verified-stay offers. Pure Ed25519 (EdDSA) verification of a host-domain
// signed offer against the host's own JWKS document — no network, no registry,
// no third-party crypto.

export { verifyCompactJws } from "./src/jws.js";
export { verifyOffer } from "./src/offer.js";
export { safeToQuote, quoteChecks, QuoteFailure } from "./src/quote.js";
export { Status, Reason } from "./src/status.js";
