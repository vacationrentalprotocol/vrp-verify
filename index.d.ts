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

export type HostDomainReasonCode =
  | "malformed_domain"
  | "public_suffix"
  | "not_host_owned"
  | "closed_tld";

export type QuoteFailureCode =
  | "not_verified"
  | "availability_not_true"
  | "price_not_exact"
  | "booking_url_missing"
  | "booking_url_invalid"
  | "booking_url_host_mismatch"
  | "quote_permission_not_granted"
  | "domain_unknown"
  | "host_owned_unknown"
  | "offer_domain_mismatch"
  | HostDomainReasonCode;

export declare const QuoteFailure: {
  readonly NOT_VERIFIED: "not_verified";
  readonly AVAILABILITY_NOT_TRUE: "availability_not_true";
  readonly PRICE_NOT_EXACT: "price_not_exact";
  readonly BOOKING_URL_MISSING: "booking_url_missing";
  readonly BOOKING_URL_INVALID: "booking_url_invalid";
  readonly BOOKING_URL_HOST_MISMATCH: "booking_url_host_mismatch";
  readonly QUOTE_PERMISSION_NOT_GRANTED: "quote_permission_not_granted";
  readonly DOMAIN_UNKNOWN: "domain_unknown";
  readonly HOST_OWNED_UNKNOWN: "host_owned_unknown";
  readonly OFFER_DOMAIN_MISMATCH: "offer_domain_mismatch";
  readonly MALFORMED_DOMAIN: "malformed_domain";
  readonly PUBLIC_SUFFIX: "public_suffix";
  readonly NOT_HOST_OWNED: "not_host_owned";
  readonly CLOSED_TLD: "closed_tld";
};

export declare const HostDomainReason: {
  readonly MALFORMED_DOMAIN: "malformed_domain";
  readonly PUBLIC_SUFFIX: "public_suffix";
  readonly NOT_HOST_OWNED: "not_host_owned";
  readonly CLOSED_TLD: "closed_tld";
};

/** The ICANN section of the Public Suffix List and the Specification 13 TLDs (spec §2). */
export interface HostOwnedLists {
  icannRules: readonly string[];
  specification13Tlds: readonly string[];
}

/** What the caller knows and this package cannot fetch (spec §2, §7). */
export interface QuoteContext {
  /** The domain being verified: the host of the URL the offer was requested from, before any redirect. */
  domain?: string;
  /** Both lists, fetched by the caller from PSL_URL and GTLDS_URL. */
  hostOwnedLists?: HostOwnedLists;
}

export interface QuoteCheckResult {
  ok: boolean;
  failures: QuoteFailureCode[];
}

export declare const PSL_URL: "https://publicsuffix.org/list/public_suffix_list.dat";
export declare const GTLDS_URL: "https://www.icann.org/resources/registries/gtlds/v2/gtlds.json";
export declare const CLOSED_TLDS: readonly ["booking", "hotels"];

/** Spec §2: null when `domain` is host-owned, else the reason. Throws TypeError without usable lists. */
export declare function checkHostOwned(domain: string, lists: HostOwnedLists): HostDomainReasonCode | null;

/** The registrable domain of `host` under ICANN-section rules, or null for a public suffix. */
export declare function registrableDomain(host: string, rules: readonly string[]): string | null;

/** The ICANN-section rules of a Public Suffix List document, or null. */
export declare function icannRulesFromPsl(text: string): string[] | null;

/** The Specification 13 TLDs of ICANN's parsed gTLD list, or null (also when it marks none). */
export declare function specification13FromGtlds(json: unknown): string[] | null;

/** Verify a compact JWS against a JWKS, resolving the key by header `kid`. */
export declare function verifyCompactJws(compactJws: string, jwksDoc: Jwks): CompactJwsResult;

/** Verify a signed VRP verified-stay-offer against a host-domain JWKS. */
export declare function verifyOffer(params: VerifyOfferParams): OfferVerificationResult;

/**
 * Evaluate the offline-checkable Safe-to-Quote conditions (spec §7, §5.1, §2)
 * against a verifyOffer() result. Without `context.domain` and
 * `context.hostOwnedLists` the result fails with `domain_unknown` or
 * `host_owned_unknown`. Fetching and the discovery document remain the caller's.
 */
export declare function quoteChecks(verification: OfferVerificationResult, context?: QuoteContext): QuoteCheckResult;

/**
 * True only when every offline-checkable Safe-to-Quote condition passes
 * (signature, freshness, availability, exact price, booking-URL host pinning,
 * agent permission, host-owned domain, offer bound to the fetched domain).
 * Without a context it is false.
 */
export declare function safeToQuote(verification: OfferVerificationResult, context?: QuoteContext): boolean;
