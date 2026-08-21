// Test-only signing helper. Derives the SAME throwaway conformance test key
// as vrp-spec scripts/conformance.mjs: the seed is SHA-256 of a fixed, public,
// documented label. It is NOT a real host key and signs only offers for the
// reserved `example-host.invalid` domain. This file is not shipped in the
// npm package (test/ is excluded by the package.json `files` allowlist).

import { createHash, createPrivateKey, sign } from "node:crypto";

export const SEED_LABEL = "VRP v0.1 conformance test vector key - DO NOT USE";
export const KID = "example-host.invalid-test-vector-2026";

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

const seed = createHash("sha256").update(SEED_LABEL).digest();
const privateKey = createPrivateKey({
  key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
  format: "der",
  type: "pkcs8",
});

const b64url = (buf) => Buffer.from(buf).toString("base64url");

/** Sign an offer payload into a compact JWS with the conformance test key. */
export function signOffer(offer, { kid = KID } = {}) {
  const header = { alg: "EdDSA", typ: "JWT", kid };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(offer))}`;
  const signature = sign(null, Buffer.from(signingInput), privateKey);
  return `${signingInput}.${b64url(signature)}`;
}

/**
 * Sign arbitrary pre-encoded header/payload segments (for negative-path JWS
 * tests: malformed payloads, foreign headers) with the conformance test key.
 */
export function signRawSegments(b64Header, b64Payload) {
  const signingInput = `${b64Header}.${b64Payload}`;
  const signature = sign(null, Buffer.from(signingInput), privateKey);
  return `${signingInput}.${b64url(signature)}`;
}

export { b64url };

/** Deep-clone a vector's offer, apply `mutate`, and re-sign it into a fresh envelope. */
export function resignedEnvelope(baseVector, mutate) {
  const offer = structuredClone(baseVector.input.offer);
  mutate(offer);
  const jws = signOffer(offer);
  return {
    kind: "signed_verified_stay_offer",
    protocol_version: "0.1",
    offer,
    signature: { format: "jws_compact", alg: "EdDSA", kid: KID, jws },
  };
}
