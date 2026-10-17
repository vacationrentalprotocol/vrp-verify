# @vacationrentalprotocol/vrp-verify

A tiny, **zero-dependency** verifier for [VRP](https://vacationrentalprotocol.com)
(Vacation Rental Protocol) signed verified-stay offers.

It answers one question for an AI agent or client: **may I quote this offer as an
official, direct offer from the host?** It verifies an Ed25519 (EdDSA) signature
over the offer against the **host domain's own JWKS** — the host is the root of
trust — and then evaluates the Safe-to-Quote conditions of the VRP
specification (§7), including the host-owned domain rule (§2) and the binding of
the offer to the domain it was fetched from. There is no central registry, and
this package never contacts one.

- **Zero runtime dependencies.** Node standard library (`node:crypto`) only.
- **No network, no canonicalization.** You supply the JWKS, the domain you
  fetched from and the two public lists; the signature is checked over the
  exact bytes as sent. The evaluation instant is injectable
  (`now`) and defaults to the system clock; the crypto layer itself never
  consults a clock.
- **Fail-closed.** Only a full pass is quoteable.
- **Conformance-tested** against the public VRP offer vectors and host-domain
  vectors.

## Install

```sh
npm install @vacationrentalprotocol/vrp-verify
```

Requires Node.js >= 18.

**Upgrading from 0.1.x.** 0.2.0 changes what passes the gate: `safeToQuote()`
and `quoteChecks()` now need the domain you fetched from and the two public
lists, and without them they fail closed. A dependency range such as `^0.1.1`
does not pick up 0.2.0 (under semantic versioning a caret range below 1.0 stays
within its minor version); change the range to `^0.2.0` and pass the context.

## Usage

```js
import {
  verifyOffer, safeToQuote, quoteChecks, discoveryChecks,
  icannRulesFromPsl, specification13TldsFromGtlds,
} from "@vacationrentalprotocol/vrp-verify";

// The two public lists (spec §2), fetched and cached by you:
//   https://publicsuffix.org/list/public_suffix_list.dat
//   https://www.icann.org/resources/registries/gtlds/v2/gtlds.json
const lists = {
  icannRules: icannRulesFromPsl(pslText),
  specification13Tlds: specification13TldsFromGtlds(gtldsJson),
};

// `fetchedDomain` is the host of the URLs you requested; `discovery` is
// https://<fetchedDomain>/.well-known/vacation-rental.json, and `jwks` and
// `envelope` come from the jwks_url and offer endpoint it names.
if (discoveryChecks(discovery, { fetchedDomain }).length > 0) throw new Error("not a VRP node");
const result = verifyOffer({ envelope, jwks, now: new Date() });

if (safeToQuote(result, { fetchedDomain, lists })) {
  // Signature valid, offer fresh, the offer names the domain it came from,
  // that domain is host-owned, availability true, price exact, booking URL a
  // node URL, agent permission granted. Quote result.payload as an official
  // direct offer.
} else {
  const { failures } = quoteChecks(result, { fetchedDomain, lists });
  console.warn(result.status, failures); // do NOT quote
}
```

Without `fetchedDomain` or `lists` the gate fails closed (`fetched_domain_unknown`,
`host_owned_unknown`).

## What this package checks — and what it does not

VRP spec **§7 (Safe-to-Quote Rules)**, with the host-owned domain rule of §2:

| # | condition | where |
| - | --------- | ----- |
| 1 | the discovery document declares `protocol: "vacation-rental-protocol"` and `protocol_version: "0.1"`, its `canonical_domain` is the domain it was fetched from, and its `jwks_url` and `verified_stay_offer_endpoint` are node URLs | `discoveryChecks` |
| 2 | the JWKS holds the key the JWS header's `kid` names (a header without `kid` names none) | `verifyOffer` |
| 3 | the compact JWS verifies against the host-domain JWKS | `verifyOffer` |
| 4 | the signed payload matches the returned offer | `verifyOffer` |
| 5 | `valid_until` is present and fresh | `verifyOffer` |
| 6 | the signed `canonical_domain` is the domain the offer was fetched from | `quoteChecks` |
| 7 | that domain is host-owned (§2): its own registrable domain under the ICANN section of the Public Suffix List, rules compared in A-label form, not under a brand or closed top-level domain | `quoteChecks` |
| 8 | `availability.available` is true | `quoteChecks` |
| 9 | `price.exact` is true | `quoteChecks` |
| 10 | a direct booking URL is present and is a node URL (§2, §5.1): `https`, host `canonical_domain` or `www.` + it, no userinfo, default port | `quoteChecks` |
| 11 | `agent_permission.may_quote_as_official_direct_offer` is true | `quoteChecks` |

**Fetching is yours.** This package has no network access: you fetch the
discovery document, the JWKS and the offer over HTTPS from the node's domain,
with your own caching and rotation policy, and you follow a redirect only when
`checkRedirects()` accepts its target. You also fetch and cache the two public
lists.

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
verdict. `safeToQuote()` / `quoteChecks()` layer the §7 policy conditions on
top; `quoteChecks()` names each failed condition
(`fetched_domain_unknown`, `offer_domain_mismatch`, `host_owned_unknown`,
`not_host_owned`, `availability_not_true`, `price_not_exact`,
`booking_url_missing`, `booking_url_invalid`, `booking_url_host_mismatch`,
`quote_permission_not_granted`, or `not_verified`).

The domain checks are also exported on their own: `checkHostOwned`,
`checkNodeUrl`, `checkRedirects`, `discoveryChecks`, `registrableDomain`,
`CLOSED_TLDS`, `icannRulesFromPsl`, `specification13TldsFromGtlds`.

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
- The **key is the one the header names.** A JWS header without `kid`
  selects no key, even when a key in the JWKS has no `kid` either.
- The **offer is bound to the domain it was fetched from** (§7): a valid
  signature over an offer that names another domain fails the gate.
- **Only a host-owned domain is a node** (§2): a name a platform hands out
  under its own domain (the Public Suffix List's PRIVATE section does not
  count), or a name under a brand or closed top-level domain (`.amazon`,
  `.booking`, `.hotels`, …), fails the gate. Without the two lists the result
  is unknown and the gate fails closed.
- The **booking URL is a node URL** (§5.1): `https` on `canonical_domain` or
  `www.` + it, with no userinfo and no port other than the default. Another
  name under the node's domain fails the gate, even though the signature is
  valid.

Report vulnerabilities per the VRP security policy (see the vrp-spec
repository). Do not open public issues for security reports.

## Conformance

The package's test suite (in the source repository; tests are not shipped in
the npm tarball) runs this verifier against byte-identical copies of the VRP
signed-offer conformance vectors and asserts that its outcome matches each
vector's declared `expected` block on the three fields the vectors define
(`verified` / `reason` / `fresh`) — the same three-field contract the vrp-spec
reference runner checks. It also runs the domain checks against a copy of the
VRP host-domain vectors (`examples/conformance/host-domain/vectors.v0.1.json`,
53 cases) and asserts the reason each one expects. The typed statuses and the
quote gate are additional API surface on top of that contract, covered by
their own tests.

## Implement your own

VRP is an open standard. If you are building an independent verifier, the
self-describing conformance vectors and the "get listed" process are documented
in the vrp-spec repository's `IMPLEMENTATIONS.md`.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE). Built entirely
from the public VRP conformance surface; contains no vendor-specific code.
