# @vacationrentalprotocol/vrp-verify

A tiny, **zero-dependency** verifier for [VRP](https://vacationrentalprotocol.com)
(Vacation Rental Protocol) signed verified-stay offers.

It answers one question for an AI agent or client: **may I quote this offer as an
official, direct offer from the host?** It verifies an Ed25519 (EdDSA) signature
over the offer against the **host domain's own JWKS** — the host is the root of
trust — and then evaluates the offline-checkable Safe-to-Quote conditions of the
VRP specification (§7 and §4). There is no central registry, and this package
never contacts one.

- **Zero runtime dependencies.** Node standard library (`node:crypto`) only.
- **No network, no canonicalization.** You supply the JWKS; the signature is
  checked over the exact bytes as sent. The evaluation instant is injectable
  (`now`) and defaults to the system clock; the crypto layer itself never
  consults a clock.
- **Fail-closed.** Only a full pass is quoteable.
- **Conformance-tested** against the public VRP offer vectors.

## Install

```sh
npm install @vacationrentalprotocol/vrp-verify
```

Requires Node.js >= 18.

## Usage

```js
import { verifyOffer, safeToQuote, quoteChecks } from "@vacationrentalprotocol/vrp-verify";

// `envelope` is a signed_verified_stay_offer (VRP spec §5).
// `jwks` is the JSON at https://<host-domain>/.well-known/jwks.json
const result = verifyOffer({ envelope, jwks, now: new Date() });

if (safeToQuote(result)) {
  // Signature valid, offer fresh, availability true, price exact,
  // booking URL pinned to the host domain, agent permission granted.
  // Quote result.payload as an official direct offer.
} else {
  const { failures } = quoteChecks(result);
  console.warn(result.status, failures); // do NOT quote
}
```

## What this package checks — and what it does not

VRP spec **§7 (Safe-to-Quote Rules)** lists eleven conditions. This package
checks the **eight that are decidable offline** from the signed offer and the
JWKS you pass in:

| # | §7 condition | where |
| - | ------------ | ----- |
| 1 | JWKS contains an Ed25519 key matching the JWS | `verifyOffer` |
| 2 | the compact JWS verifies against the host-domain JWKS | `verifyOffer` |
| 3 | the signed payload matches the returned offer | `verifyOffer` |
| 4 | `valid_until` is present and fresh | `verifyOffer` |
| 5 | `availability.available` is true | `quoteChecks` |
| 6 | `price.exact` is true | `quoteChecks` |
| 7 | a direct booking URL is present — and, per **§4**, is an absolute `https` URL whose host is the offer's `canonical_domain` or a subdomain of it | `quoteChecks` |
| 8 | `agent_permission.may_quote_as_official_direct_offer` is true | `quoteChecks` |

**The remaining three §7 conditions are the caller's responsibility.** They
concern the *discovery document* and require network context this package
deliberately does not have:

- the discovery document is fetched from the host-owned domain,
- it declares `protocol: "vacation-rental-protocol"`,
- it declares `protocol_version: "0.1"`.

Likewise, **fetching the JWKS itself** (over HTTPS, from the host's own domain,
with your own caching and rotation policy) is yours: this package verifies
against whatever JWKS document you hand it.

### Result

`verifyOffer()` returns:

| field                 | meaning                                                        |
| --------------------- | ------------------------------------------------------------- |
| `status`              | `verified` \| `expired` \| `invalid` \| `unverifiable`        |
| `code`                | machine reason code; `null` for `verified` and `expired` (both mean the signature checked out) |
| `reason`              | short human-readable explanation                              |
| `fresh`               | `valid_until > now`; `null` whenever the verdict is not `verified`/`expired` |
| `header`              | the JWS protected header, when it could be parsed             |
| `payload`             | the signed offer payload, when available                      |
| `payloadMatchesOffer` | whether `envelope.offer` equals the signed payload; `null` when there is no plaintext offer to compare |

The four statuses:

- **verified** — signature valid **and** the offer is still fresh.
- **expired** — signature valid, but `valid_until` has passed.
- **invalid** — the presented **artifact** fails verification: a signature is
  present and does not verify, or the envelope is tampered/malformed. This is
  a statement about the envelope — per spec §9 a failed signature check leaves
  every value inside *Unknown*, so nothing in it may be cited as true **or**
  false.
- **unverifiable** — a verdict could not be reached: the signing key is absent
  from the JWKS or unusable, or `valid_until` is missing/malformed so
  freshness cannot be determined (`valid_until_unusable`). This is **never**
  reported as `invalid`, because absence of a key is not proof of forgery.

`status: "verified"` alone is **not** permission to quote — it is the crypto
verdict. `safeToQuote()` / `quoteChecks()` layer the §7/§4 policy conditions on
top; `quoteChecks()` names each failed condition
(`availability_not_true`, `price_not_exact`, `booking_url_missing`,
`booking_url_invalid`, `booking_url_host_mismatch`,
`quote_permission_not_granted`, or `not_verified`).

### Low-level

```js
import { verifyCompactJws } from "@vacationrentalprotocol/vrp-verify";

const { valid, reason, header, payload } = verifyCompactJws(compactJws, jwks);
```

`verifyCompactJws()` performs the pure JWS check only (no freshness, no
policy). Its `reason` codes match the published VRP conformance vectors.

## Security model

- The **host domain's JWKS is the trust root.** Fetch it over HTTPS from the
  host's own domain and pass it in. This package does not fetch it for you, so
  transport, caching, and rotation policy stay under your control.
- The algorithm is **pinned to EdDSA.** A JWS declaring any other `alg` is
  rejected as a downgrade attempt.
- The signature is verified over the **exact received bytes** — no
  canonicalization step to disagree on.
- A valid signature over a payload that disagrees with a plaintext
  `envelope.offer` is treated as tampering (`invalid`).
- The **booking URL is host-pinned** (§4): a signed offer whose
  `direct_booking_url` points off the host's `canonical_domain` fails the gate,
  even though its signature is valid. The pin is deliberately **stricter than
  §4's registrable-domain wording**: only the `canonical_domain` host itself
  and its subdomains pass. Deriving the registrable domain of an arbitrary
  `canonical_domain` would require a Public Suffix List (a dependency, and a
  fail-open risk if approximated), so when `canonical_domain` is itself a
  subdomain, sibling subdomains are rejected — the check can refuse a
  spec-valid URL, never accept a third-party host.

Report vulnerabilities per the VRP security policy (see the vrp-spec
repository). Do not open public issues for security reports.

## Conformance

The package's test suite (in the source repository; tests are not shipped in
the npm tarball) runs this verifier against byte-identical copies of the VRP
signed-offer conformance vectors and asserts that its outcome matches each
vector's declared `expected` block on the three fields the vectors define
(`verified` / `reason` / `fresh`) — the same three-field contract the vrp-spec
reference runner checks. The typed statuses and the quote gate are additional
API surface on top of that contract, covered by their own tests.

## Implement your own

VRP is an open standard. If you are building an independent verifier, the
self-describing conformance vectors and the "get listed" process are documented
in the vrp-spec repository's `IMPLEMENTATIONS.md`.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE). Built entirely
from the public VRP conformance surface; contains no vendor-specific code.
