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
  | "valid_until_unusable"
  | "generated_at_unusable"
  | "lifetime_not_positive"
  | "lifetime_too_long"
  | "generated_at_in_future"
  | "clock_unusable";

/** The offer rules beyond the signature (spec §5, §6, §7), in the vocabulary of the VRP offer-rules conformance vectors. */
export type OfferRuleCode =
  | "malformed_generated_at"
  | "malformed_valid_until"
  | "lifetime_not_positive"
  | "lifetime_too_long"
  | "generated_at_in_future"
  | "expired"
  | "request_missing"
  | "invalid_check_in"
  | "invalid_check_out"
  | "check_out_not_after_check_in"
  | "check_in_in_past"
  | "invalid_language"
  | "asked_stay_unknown"
  | "request_mismatch";

export declare const OfferRule: {
  readonly MALFORMED_GENERATED_AT: "malformed_generated_at";
  readonly MALFORMED_VALID_UNTIL: "malformed_valid_until";
  readonly LIFETIME_NOT_POSITIVE: "lifetime_not_positive";
  readonly LIFETIME_TOO_LONG: "lifetime_too_long";
  readonly GENERATED_AT_IN_FUTURE: "generated_at_in_future";
  readonly EXPIRED: "expired";
  readonly REQUEST_MISSING: "request_missing";
  readonly INVALID_CHECK_IN: "invalid_check_in";
  readonly INVALID_CHECK_OUT: "invalid_check_out";
  readonly CHECK_OUT_NOT_AFTER_CHECK_IN: "check_out_not_after_check_in";
  readonly CHECK_IN_IN_PAST: "check_in_in_past";
  readonly INVALID_LANGUAGE: "invalid_language";
  readonly ASKED_STAY_UNKNOWN: "asked_stay_unknown";
  readonly REQUEST_MISMATCH: "request_mismatch";
};

/** Spec §5: the longest lifetime a signed offer may have, in seconds. */
export declare const MAX_LIFETIME_SECONDS: 900;
/** Spec §6: how far ahead of the verifier's clock generated_at may be, in seconds. */
export declare const CLOCK_SKEW_SECONDS: 60;
/** Spec §5: the form of request.language. */
export declare const LANGUAGE_TAG: RegExp;

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
  readonly GENERATED_AT_UNUSABLE: "generated_at_unusable";
  readonly LIFETIME_NOT_POSITIVE: "lifetime_not_positive";
  readonly LIFETIME_TOO_LONG: "lifetime_too_long";
  readonly GENERATED_AT_IN_FUTURE: "generated_at_in_future";
  readonly CLOCK_UNUSABLE: "clock_unusable";
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
  /** The instant the lifetime was judged at (ISO date-time); null when the verdict was reached before the clock mattered. */
  evaluatedAt: string | null;
  /** Every lifetime rule (spec §5, §6) the signed payload breaks at that instant; empty when none or when the signature did not verify. */
  reasons: OfferRuleCode[];
}

export interface VerifyOfferParams {
  envelope?: Record<string, unknown>;
  jws?: string;
  jwks: Jwks;
  now?: Date | string | number;
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
  | HostDomainReasonCode
  | OfferRuleCode;

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
  readonly MALFORMED_GENERATED_AT: "malformed_generated_at";
  readonly MALFORMED_VALID_UNTIL: "malformed_valid_until";
  readonly LIFETIME_NOT_POSITIVE: "lifetime_not_positive";
  readonly LIFETIME_TOO_LONG: "lifetime_too_long";
  readonly GENERATED_AT_IN_FUTURE: "generated_at_in_future";
  readonly EXPIRED: "expired";
  readonly REQUEST_MISSING: "request_missing";
  readonly INVALID_CHECK_IN: "invalid_check_in";
  readonly INVALID_CHECK_OUT: "invalid_check_out";
  readonly CHECK_OUT_NOT_AFTER_CHECK_IN: "check_out_not_after_check_in";
  readonly CHECK_IN_IN_PAST: "check_in_in_past";
  readonly INVALID_LANGUAGE: "invalid_language";
  readonly ASKED_STAY_UNKNOWN: "asked_stay_unknown";
  readonly REQUEST_MISMATCH: "request_mismatch";
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

/** The stay the caller asked the offer endpoint for (spec §4, §7). */
export interface AskedStay {
  /** Arrival date, YYYY-MM-DD. */
  check_in: string;
  /** Departure date, YYYY-MM-DD. */
  check_out: string;
  /** Guest count, an integer of at least 1. */
  guests: number;
}

/** What the caller knows and this package cannot fetch (spec §2, §4, §7). */
export interface QuoteContext {
  /** The domain being verified: the host of the URL the offer was requested from, before any redirect. */
  domain?: string;
  /** Both lists, fetched by the caller from PSL_URL and GTLDS_URL. */
  hostOwnedLists?: HostOwnedLists;
  /** The stay asked for. Without it the gate fails with `asked_stay_unknown` (0.3.0). */
  request?: AskedStay;
  /** The quoting instant; default: the instant the verification was judged at. */
  now?: Date | string | number;
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
 * The reasons a signed payload is not quotable under the offer rules beyond the
 * signature (spec §5, §6, §7), in the order of the VRP offer-rules conformance
 * vectors; an empty array when it meets them. `now` is the evaluation instant
 * (default: now); `asked` is the stay the agent asked for, or null when unknown.
 */
export declare function checkOfferRules(
  payload: Record<string, unknown> | null | undefined,
  options?: { now?: Date | string | number; asked?: AskedStay | null },
): OfferRuleCode[];

/**
 * Evaluate the offline-checkable Safe-to-Quote conditions (spec §7, §5, §5.1,
 * §6, §2) against a verifyOffer() result. Without `context.domain`,
 * `context.hostOwnedLists` and `context.request` the result fails with
 * `domain_unknown`, `host_owned_unknown` or `asked_stay_unknown`. Fetching and
 * the discovery document remain the caller's.
 */
export declare function quoteChecks(verification: OfferVerificationResult, context?: QuoteContext): QuoteCheckResult;

/**
 * True only when every offline-checkable Safe-to-Quote condition passes
 * (signature, lifetime and freshness, the dates and the stay asked for,
 * availability, exact price, booking-URL host pinning, agent permission,
 * host-owned domain, offer bound to the fetched domain). Without a context it
 * is false.
 */
export declare function safeToQuote(verification: OfferVerificationResult, context?: QuoteContext): boolean;
