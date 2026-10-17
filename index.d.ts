// Type declarations for @vacationrentalprotocol/vrp-verify.
// Hand-written: the package ships plain ESM and has no build step.

export type OfferStatus = "verified" | "expired" | "invalid" | "unverifiable";

export type ReasonCode =
  | "malformed_jws"
  | "malformed_header"
  | "unexpected_alg"
  | "kid_not_in_jwks"
  | "unsupported_key"
  | "signature_mismatch"
  | "malformed_payload"
  | "no_jws"
  | "payload_offer_mismatch"
  | "valid_until_unusable";

export declare const Status: {
  readonly VERIFIED: "verified";
  readonly EXPIRED: "expired";
  readonly INVALID: "invalid";
  readonly UNVERIFIABLE: "unverifiable";
};

export declare const Reason: {
  readonly MALFORMED_JWS: "malformed_jws";
  readonly MALFORMED_HEADER: "malformed_header";
  readonly UNEXPECTED_ALG: "unexpected_alg";
  readonly KID_NOT_IN_JWKS: "kid_not_in_jwks";
  readonly UNSUPPORTED_KEY: "unsupported_key";
  readonly SIGNATURE_MISMATCH: "signature_mismatch";
  readonly MALFORMED_PAYLOAD: "malformed_payload";
  readonly NO_JWS: "no_jws";
  readonly PAYLOAD_OFFER_MISMATCH: "payload_offer_mismatch";
  readonly VALID_UNTIL_UNUSABLE: "valid_until_unusable";
};

export interface Jwk {
  kty: string;
  crv: string;
  kid?: string;
  x: string;
  [k: string]: unknown;
}

export interface Jwks {
  keys?: Jwk[];
}

export interface CompactJwsResult {
  valid: boolean;
  reason: ReasonCode | null;
  header?: Record<string, unknown>;
  payload?: Record<string, unknown>;
}

export interface OfferVerificationResult {
  status: OfferStatus;
  code: ReasonCode | null;
  reason: string;
  fresh: boolean | null;
  header: Record<string, unknown> | null;
  payload: Record<string, unknown> | null;
  payloadMatchesOffer: boolean | null;
}

export interface VerifyOfferParams {
  envelope?: Record<string, unknown>;
  jws?: string;
  jwks: Jwks;
  now?: Date | string;
}

export type QuoteFailureCode =
  | "not_verified"
  | "availability_not_true"
  | "price_not_exact"
  | "booking_url_missing"
  | "booking_url_invalid"
  | "booking_url_host_mismatch"
  | "quote_permission_not_granted"
  | "fetched_domain_unknown"
  | "offer_domain_mismatch"
  | "host_owned_unknown"
  | "not_host_owned";

export declare const QuoteFailure: {
  readonly NOT_VERIFIED: "not_verified";
  readonly AVAILABILITY_NOT_TRUE: "availability_not_true";
  readonly PRICE_NOT_EXACT: "price_not_exact";
  readonly BOOKING_URL_MISSING: "booking_url_missing";
  readonly BOOKING_URL_INVALID: "booking_url_invalid";
  readonly BOOKING_URL_HOST_MISMATCH: "booking_url_host_mismatch";
  readonly QUOTE_PERMISSION_NOT_GRANTED: "quote_permission_not_granted";
  readonly FETCHED_DOMAIN_UNKNOWN: "fetched_domain_unknown";
  readonly OFFER_DOMAIN_MISMATCH: "offer_domain_mismatch";
  readonly HOST_OWNED_UNKNOWN: "host_owned_unknown";
  readonly NOT_HOST_OWNED: "not_host_owned";
};

/** The ICANN section of the Public Suffix List and the Specification 13 top-level domains of ICANN's gTLD list. */
export interface DomainLists {
  icannRules: string[];
  specification13Tlds: string[];
}

export interface QuoteContext {
  /** The host of the URL the offer was requested from. */
  fetchedDomain?: string;
  /** Without them the host-owned check is unknown and the gate fails closed. */
  lists?: DomainLists;
}

export type HostOwnedReason = "lists_unavailable" | "malformed_domain" | "public_suffix" | "not_host_owned" | "closed_tld";
export type NodeUrlReason = "url_invalid" | "url_not_https" | "url_userinfo" | "url_port" | "url_host_mismatch";
export type DiscoveryFailure =
  | "protocol"
  | "protocol_version"
  | "discovery_domain_mismatch"
  | "jwks_url_not_node_url"
  | "offer_endpoint_not_node_url";

/** spec/v0.1.md §2: the closed top-level domains the standard names. */
export declare const CLOSED_TLDS: readonly string[];
/** The rules of the ICANN section of public_suffix_list.dat. */
export declare function icannRulesFromPsl(text: string): string[];
/** The top-level domains ICANN's gtlds.json marks "specification13": true. */
export declare function specification13TldsFromGtlds(doc: unknown): string[];
/** The registrable domain of `host` under `rules`, or null when `host` is a public suffix. */
export declare function registrableDomain(host: string, rules: string[]): string | null;
/** spec §2: null when `domain` is a host-owned domain. */
export declare function checkHostOwned(domain: unknown, lists?: DomainLists): HostOwnedReason | null;
/** spec §2, §5.1: null when `url` is a node URL of `canonicalDomain`. */
export declare function checkNodeUrl(url: unknown, canonicalDomain: unknown): NodeUrlReason | null;
/** spec §2: null when every redirect target is a node URL of `canonicalDomain`. */
export declare function checkRedirects(chain: string[], canonicalDomain: string): "redirect_not_https" | "redirect_off_node" | null;
/** spec §2, §7: the failed conditions of a discovery document fetched from `fetchedDomain`; empty when it passes. */
export declare function discoveryChecks(discovery: unknown, context: { fetchedDomain: string }): DiscoveryFailure[];

export interface QuoteCheckResult {
  ok: boolean;
  failures: QuoteFailureCode[];
}

/** Verify a compact JWS against a JWKS, resolving the key by header `kid`; a header without `kid` selects no key. */
export declare function verifyCompactJws(compactJws: string, jwksDoc: Jwks): CompactJwsResult;

/** Verify a signed VRP verified-stay-offer against a host-domain JWKS. */
export declare function verifyOffer(params: VerifyOfferParams): OfferVerificationResult;

/**
 * Evaluate the Safe-to-Quote conditions (spec §7) against a verifyOffer()
 * result: the offer names the domain it was fetched from, that domain is
 * host-owned (§2), the booking URL is a node URL (§5.1), and the availability,
 * price and permission flags. The discovery document is checked with
 * discoveryChecks().
 */
export declare function quoteChecks(verification: OfferVerificationResult, context?: QuoteContext): QuoteCheckResult;

/** True only when quoteChecks() passes. Without a context it is always false — fail closed. */
export declare function safeToQuote(verification: OfferVerificationResult, context?: QuoteContext): boolean;
