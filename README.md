# @vacationrentalprotocol/vrp-verify

A tiny, **zero-dependency** verifier for [VRP](https://vacationrentalprotocol.com)
(Vacation Rental Protocol) signed verified-stay offers.

It answers one question for an AI agent or client: **may I quote this offer as an
official, direct offer from the host?** It verifies an Ed25519 (EdDSA) signature
over the offer against the **host domain's own JWKS** — the host is the root of
trust — and then evaluates the offline-checkable Safe-to-Quote conditions of the
VRP specification (§7 and §5.1), including that the offer comes from a
**host-owned domain** (§2): the host's own registrable domain, never a name
under a platform's, marketplace's or site builder's domain. There is no central
registry, and this package never contacts one.

- **Zero runtime dependencies.** Node standard library (`node:crypto`) only.
- **No network, no canonicalization.** You supply the JWKS, the domain you
  fetched the offer from, and two public lists (the Public Suffix List and
  ICANN's gTLD list); the signature is checked over the exact bytes as sent. The evaluation instant is injectable
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
import {
  verifyOffer,
  quoteChecks,
  icannRulesFromPsl,
  specification13FromGtlds,
  PSL_URL,
  GTLDS_URL,
} from "@vacationrentalprotocol/vrp-verify";

// The two public lists VRP §2 reads. Fetch them yourself and cache them
// (both change rarely); this package never fetches anything.
const hostOwnedLists = {
  icannRules: icannRulesFromPsl(await (await fetch(PSL_URL)).text()),
  specification13Tlds: specification13FromGtlds(await (await fetch(GTLDS_URL)).json()),
};

// `domain` is the domain you are verifying: the host of the URL you requested,
// e.g. https://<domain>/.well-known/vacation-rental.json, before any redirect.
// `envelope` is a signed_verified_stay_offer (VRP spec §5).
// `jwks` is the JSON at https://<domain>/.well-known/jwks.json
const result = verifyOffer({ envelope, jwks, now: new Date() });
const { ok, failures } = quoteChecks(result, { domain, hostOwnedLists });

if (ok) {
  // Signature valid, offer fresh, availability true, price exact, booking URL
  // pinned to the host domain, agent permission granted, and the offer names
  // the host-owned domain it was fetched from.
  // Quote result.payload as an official direct offer.
} else {
  console.warn(result.status, failures); // do NOT quote
}
```

`safeToQuote(result, { domain, hostOwnedLists })` returns the same verdict as a
boolean. **Without `domain` and `hostOwnedLists` the gate is closed**
(`domain_unknown`, `host_owned_unknown`): an offer whose domain is not checked
is unknown (§2, §9), never safe to quote.

### Changed in 0.2.0

Up to 0.1.2, `safeToQuote(result)` and `quoteChecks(result)` did not check the
domain: as this README said, whether the offer came from a host-owned domain
was the caller's responsibility. A caller that skipped that check could quote
an offer signed for a name under another party's domain. From 0.2.0 the gate
checks it, and fails closed when the caller does not pass the domain and the
lists. Update your calls to pass `{ domain, hostOwnedLists }`.

## What this package checks — and what it does not

VRP spec **§7 (Safe-to-Quote Rules)** lists eleven conditions. This package
checks the **eight that are decidable offline** from the signed offer and the
JWKS you pass in, and the **host-owned domain** (§2) from the domain and the
lists you pass in:

| # | §7 condition | where |
| - | ------------ | ----- |
| 1 | JWKS contains an Ed25519 key matching the JWS | `verifyOffer` |
| 2 | the compact JWS verifies against the host-domain JWKS | `verifyOffer` |
| 3 | the signed payload matches the returned offer | `verifyOffer` |
| 4 | `valid_until` is present and fresh | `verifyOffer` |
| 5 | `availability.available` is true | `quoteChecks` |
| 6 | `price.exact` is true | `quoteChecks` |
| 7 | a direct booking URL is present — and, per **§5.1**, is a node URL (§2): `https`, host the offer's `canonical_domain` or `www.` followed by it, no userinfo, the default port | `quoteChecks` |
| 8 | `agent_permission.may_quote_as_official_direct_offer` is true | `quoteChecks` |
| 9 | the signed `canonical_domain` is the domain the offer was fetched from (§7) | `quoteChecks`, from `domain` |
| 10 | that domain is host-owned (§2): lowercase A-labels, its own registrable domain under the **ICANN section** of the Public Suffix List (the PRIVATE section does not count), not under a brand or closed top-level domain (Specification 13, `booking`, `hotels`); no usable lists = unknown | `quoteChecks`, from `hostOwnedLists` |

**What remains the caller's responsibility** needs network context this package
deliberately does not have:

- fetching over HTTPS and following a redirect only to a node URL of the
  domain (§2),
- the discovery document itself: its `canonical_domain` is the domain it was
  fetched from, and it declares `protocol: "vacation-rental-protocol"` and
  `protocol_version: "0.1"`.

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
verdict. `safeToQuote()` / `quoteChecks()` layer the §7/§5.1 policy conditions on
top; `quoteChecks()` names each failed condition
(`availability_not_true`, `price_not_exact`, `booking_url_missing`,
`booking_url_invalid`, `booking_url_host_mismatch`,
`quote_permission_not_granted`, `domain_unknown`, `host_owned_unknown`,
`offer_domain_mismatch`, `malformed_domain`, `public_suffix`, `not_host_owned`,
`closed_tld`, or `not_verified`). The host-domain codes are the ones the VRP
host-domain conformance vectors use, and `checkHostOwned(domain, lists)` is
exported for checking a domain on its own.

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
- The **booking URL is a node URL** (§5.1, §2): a signed offer whose
  `direct_booking_url` is not on the offer's `canonical_domain` or `www.`
  followed by it fails the gate, even though its signature is valid. Any other
  name under the domain (`airbnb.example`) fails too: it may be served by
  another party. So do userinfo and a port other than the `https` default.
- The **node is a host-owned domain** (§2): a name a platform, marketplace,
  site builder or operator hands out under its own domain (`villa.wixsite.com`,
  `villa.example-platform.com`) or a name under a brand or closed top-level
  domain (`villa.booking`) is never a VRP node, whoever signs for it. Without
  the domain and both lists the gate is closed.

Report vulnerabilities per the VRP security policy (see the vrp-spec
repository). Do not open public issues for security reports.

## Conformance

The package's test suite (in the source repository; tests are not shipped in
the npm tarball) runs this verifier against byte-identical copies of the VRP
signed-offer conformance vectors and asserts that its outcome matches each
vector's declared `expected` block on the three fields the vectors define
(`verified` / `reason` / `fresh`) — the same three-field contract the vrp-spec
reference runner checks. It also runs the gate against a byte-identical copy of
the VRP host-domain vectors (`host_owned`, `real_world`, the offer-binding cases
for the signed offer, and the booking-URL node URLs). The typed statuses and
the quote gate are additional API surface on top of that contract, covered by
their own tests.

## Implement your own

VRP is an open standard. If you are building an independent verifier, the
self-describing conformance vectors and the "get listed" process are documented
in the vrp-spec repository's `IMPLEMENTATIONS.md`.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE). Built entirely
from the public VRP conformance surface; contains no vendor-specific code.
