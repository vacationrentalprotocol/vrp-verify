// The two names of the one wire format, and the two names of the one signing
// operation (VRP 1.0 candidate: spec §2, §3, §5, §7, §9; ADR 0013, ADR 0017).
//
// `"1.0"` and `"0.1"` name the same wire format. A discovery document declares
// a version and a signed offer declares its own; they are two declarations and
// are checked separately. A declared value is compared as written. An absent
// value, or any other value of any type, leaves the document or the offer
// unknown (§9): nothing is filled in for the node (§8, fail closed).
//
// `Ed25519` (RFC 9864) and `EdDSA` (RFC 8037) name the same operation in a JWS
// protected header; the names are case-sensitive (RFC 7515 §4.1.1).

export const VRP_PROTOCOL = "vacation-rental-protocol";
export const KNOWN_PROTOCOL_VERSIONS = Object.freeze(["1.0", "0.1"]);
export const SIGNATURE_ALGS = Object.freeze(["Ed25519", "EdDSA"]);

/** Reason codes for a declared protocol and version; the vocabulary of the vrp-spec vectors. */
export const VersionReason = Object.freeze({
  MALFORMED_DISCOVERY: "malformed_discovery",
  MALFORMED_PAYLOAD: "malformed_payload",
  UNEXPECTED_PROTOCOL: "unexpected_protocol",
  MISSING_PROTOCOL_VERSION: "missing_protocol_version",
  UNSUPPORTED_VERSION: "unsupported_version",
});

const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/** A declared `protocol_version`: null when known, else a VersionReason code. */
export function checkDeclaredVersion(value) {
  if (value === undefined) return VersionReason.MISSING_PROTOCOL_VERSION;
  if (typeof value !== "string" || !KNOWN_PROTOCOL_VERSIONS.includes(value)) return VersionReason.UNSUPPORTED_VERSION;
  return null;
}

/**
 * §2 and §7: the discovery document declares `protocol:
 * "vacation-rental-protocol"` and a known `protocol_version`. This is a rule
 * about the discovery document only.
 *
 * @param {unknown} discovery the parsed discovery document
 * @returns {string|null} null when it passes, else a VersionReason code
 */
export function checkDiscoveryVersion(discovery) {
  if (!isRecord(discovery)) return VersionReason.MALFORMED_DISCOVERY;
  if (discovery.protocol !== VRP_PROTOCOL) return VersionReason.UNEXPECTED_PROTOCOL;
  return checkDeclaredVersion(discovery.protocol_version);
}

/**
 * §5 and §9: the signed payload declares a known `protocol_version`. Pass the
 * SIGNED payload, never the unsigned envelope beside it.
 *
 * @param {unknown} payload the payload decoded from a verified JWS
 * @returns {string|null} null when it passes, else a VersionReason code
 */
export function checkOfferVersion(payload) {
  if (!isRecord(payload)) return VersionReason.MALFORMED_PAYLOAD;
  return checkDeclaredVersion(payload.protocol_version);
}
