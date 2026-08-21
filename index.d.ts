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
  | "quote_permission_not_granted";

export declare const QuoteFailure: {
  readonly NOT_VERIFIED: "not_verified";
  readonly AVAILABILITY_NOT_TRUE: "availability_not_true";
  readonly PRICE_NOT_EXACT: "price_not_exact";
  readonly BOOKING_URL_MISSING: "booking_url_missing";
  readonly BOOKING_URL_INVALID: "booking_url_invalid";
  readonly BOOKING_URL_HOST_MISMATCH: "booking_url_host_mismatch";
  readonly QUOTE_PERMISSION_NOT_GRANTED: "quote_permission_not_granted";
};

export interface QuoteCheckResult {
  ok: boolean;
  failures: QuoteFailureCode[];
}

/** Verify a compact JWS against a JWKS, resolving the key by header `kid`. */
export declare function verifyCompactJws(compactJws: string, jwksDoc: Jwks): CompactJwsResult;

/** Verify a signed VRP verified-stay-offer against a host-domain JWKS. */
export declare function verifyOffer(params: VerifyOfferParams): OfferVerificationResult;

/**
 * Evaluate the offline-checkable Safe-to-Quote conditions (spec §7, §4)
 * against a verifyOffer() result. The three discovery-document conditions
 * of §7 remain the caller's responsibility.
 */
export declare function quoteChecks(verification: OfferVerificationResult): QuoteCheckResult;

/**
 * True only when every offline-checkable Safe-to-Quote condition passes
 * (signature, freshness, availability, exact price, booking-URL host pinning,
 * agent permission). Discovery-document checks remain the caller's.
 */
export declare function safeToQuote(verification: OfferVerificationResult): boolean;
