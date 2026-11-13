# @vacationrentalprotocol/vrp-verify

A tiny, **zero-dependency** verifier for [VRP](https://vacationrentalprotocol.com)
(Vacation Rental Protocol) signed verified-stay offers.

It answers one question for an AI agent or client: **may I quote this offer as an
official, direct offer from the host?** It verifies an Ed25519 (EdDSA) signature
over the offer against the **host domain's own JWKS** — the host is the root of
trust — and then evaluates the offline-checkable Safe-to-Quote conditions of the
VRP specification (§7, with §5, §5.1 and §6): the offer's **lifetime** (a
positive window of at most 900 seconds, not started in the future, not yet
passed), the **dates** of the stay, that the signed stay is **the stay you
asked for**, and that the offer comes from a **host-owned domain** (§2): the
host's own registrable domain, never a name under a platform's, marketplace's
or site builder's domain. Every value is read from the signed payload; nothing
is taken from an unsigned part of the envelope. There is no central registry,
and this package never contacts one.

- **Zero runtime dependencies.** Node standard library (`node:crypto`) only.
- **No network, no canonicalization.** You supply the JWKS, the domain you
  fetched the offer from, the stay you asked for, and two public lists (the
  Public Suffix List and ICANN's gTLD list); the signature is checked over the
  exact bytes as sent. The evaluation instant is injectable (`now`) and
  defaults to the system clock; the crypto layer itself never consults a clock.
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
// `request` is the stay you asked the offer endpoint for (§4): the same
// check_in, check_out and guests you sent, as you sent them.
const request = { check_in: "2027-03-08", check_out: "2027-03-12", guests: 2 };
// `discovery` is the parsed JSON you fetched from
// https://<domain>/.well-known/vacation-rental.json (§2).
const result = verifyOffer({ envelope, jwks, now: new Date() });
const { ok, failures } = quoteChecks(result, { domain, hostOwnedLists, discovery, request });

if (ok) {
  // Signature valid; generated_at and valid_until well-formed, a lifetime of
  // at most 900 seconds, not started in the future, still fresh; the signed
  // stay is the stay you asked for, on dates that exist and have not passed;
  // availability true, price exact, booking URL pinned to the host domain,
  // agent permission granted, the offer names the host-owned domain it was
  // fetched from, and the discovery document and the signed offer each
  // declare a known protocol version. Quote result.payload as an official
  // direct offer.
} else {
  console.warn(result.status, result.code, failures); // do NOT quote
}
```

`safeToQuote(result, { domain, hostOwnedLists, discovery, request })` returns
the same verdict as a boolean. **Without `domain`, `hostOwnedLists`,
`discovery` and `request` the gate is closed** (`domain_unknown`,
`host_owned_unknown`, `discovery_unknown`, `asked_stay_unknown`): an offer whose
domain is not checked, whose node's declared protocol version is not read, or
whose stay cannot be compared with the stay asked for, is unknown (§2, §7, §9),
never safe to quote.

### Unreleased: VRP 1.0 candidate

Not in any published version. This follows the VRP 1.0 candidate text in
vrp-spec pull request 187, which is a draft and not adopted; the rules below
may change with it.

VRP 1.0 keeps the v0.1 wire format and gives it a second name. A discovery
document and a signed offer each declare `protocol_version`, `"1.0"` or
`"0.1"`, and the two declarations are checked separately. The value is compared
as written: `"1.0.0"`, `" 1.0"`, the number `1` and `null` are not `"1.0"`. In
a JWS protected header, `Ed25519` (RFC 9864) and `EdDSA` (RFC 8037) name the
same signing operation, and both are accepted; the name is case-sensitive.

- `verifyCompactJws()` accepts the header `alg` `Ed25519` as well as `EdDSA`.
  Any other name is `unexpected_alg`, as before. The key's own `alg` may be
  either name too; any other label, or none, is `unsupported_key`, as in
  0.3.1.
- `verifyOffer()` reads `protocol_version` from the **signed payload**. Any
  value other than `"1.0"` or `"0.1"`, or none, gives `unverifiable` with the
  code `unsupported_version` or `missing_protocol_version`, however genuine the
  signature. Up to 0.3.1 the signed version is not read. The unsigned
  envelope's own `protocol_version` is not consulted.
- `quoteChecks()` reads `protocol` and `protocol_version` from
  `context.discovery`, the parsed discovery document you fetched. The codes
  are `malformed_discovery`, `unexpected_protocol`, `missing_protocol_version`
  and `unsupported_version`. Without `context.discovery` the gate fails with
  `discovery_unknown`.
- `checkDiscoveryVersion(discovery)` and `checkOfferVersion(payload)` are
  exported for checking either declaration on its own.

**Migration.** A caller that upgrades without passing `context.discovery` gets
`false` from `safeToQuote()` for every offer, valid ones included
(`discovery_unknown`). A v0.1 node needs no change: `"0.1"` and `EdDSA` are
accepted as they were.

### Changed in 0.3.1

Up to 0.3.0, `verifyCompactJws()` and `verifyOffer()` used whichever key in the
JWKS carried the JWS header's `kid`, provided it was `kty: "OKP"` and
`crv: "Ed25519"`, and did not read the key's own `alg`. A key labelled with
another algorithm (`ES256`, `none`, `ed25519` in lower case) or with no `alg`
at all verified an offer, and the offer could pass the gate. VRP spec §3 and
the JWKS schema say a signing key names its `alg`, `EdDSA`. From 0.3.1 a key
whose `alg` is not exactly `EdDSA` is not a VRP signing key: the result is
`unverifiable` with the code `unsupported_key`, and the signature is never
checked against it.

**Migration.** Nothing changes for a JWKS that follows the schema. A JWKS whose
key omits `alg`, or spells it otherwise, no longer verifies; the node has to
publish the key with `alg: "EdDSA"`.

### Changed in 0.3.0

Up to 0.2.0, `verifyOffer()` read `valid_until` only, with a lenient date
parser, and `quoteChecks()` compared nothing about the stay. An offer with a
`valid_until` ten years out, or without `generated_at`, or signed for other
dates or another guest count than the ones you asked for, could pass as
`verified` and as safe to quote. From 0.3.0, `verifyOffer()` enforces spec §5
and §6 on the signed payload — `generated_at` and `valid_until` are UTC
date-times ending in `Z` that exist, `valid_until` is later than `generated_at`
and at most 900 seconds after it, `generated_at` is at most 60 seconds ahead of
`now`, and `valid_until` has not passed — and `quoteChecks()` enforces §5 and
§7 on `request`: the dates exist, `check_out` is later than `check_in`,
`check_in` is not earlier than the day before the UTC date, `language` (when
present) is a language tag, and `check_in`, `check_out` and `guests` equal the
stay you pass as `context.request`. `quoteChecks()` judges the lifetime again
at the quoting instant — `context.now` when you pass one, else the current
time — so an offer verified fresh and quoted after its `valid_until` fails with
`expired`. A `now` that cannot be read (`NaN`, an Invalid Date, an unparseable
string) fails with `clock_unusable` in `verifyOffer()`, `quoteChecks()` and
`checkOfferRules()`.

**Migration.** A caller that upgrades without passing `context.request` gets
`false` from `safeToQuote()` for every offer, valid ones included
(`asked_stay_unknown`): the gate no longer has a way to know whether the signed
stay is the one asked for. Pass `{ domain, hostOwnedLists, request }`; the
reason codes are those of the VRP offer-rules conformance vectors.

### Changed in 0.2.0

Up to 0.1.2, `safeToQuote(result)` and `quoteChecks(result)` did not check the
domain: as this README said, whether the offer came from a host-owned domain
was the caller's responsibility. A caller that skipped that check could quote
an offer signed for a name under another party's domain. From 0.2.0 the gate
checks it, and fails closed when the caller does not pass the domain and the
lists. Update your calls to pass `{ domain, hostOwnedLists }`.

## What this package checks — and what it does not

VRP spec **§7 (Safe-to-Quote Rules)** lists sixteen conditions. This package
checks the **fifteen that are decidable offline** from the signed offer, the
JWKS, the domain, the stay you asked for and the clock you pass in, the
**host-owned domain** (§2) from the domain and the lists you pass in, and what
the **discovery document declares** from the document you pass in:

| # | §7 condition | where |
| - | ------------ | ----- |
| 1 | JWKS contains an Ed25519 key matching the JWS | `verifyOffer` |
| 2 | the compact JWS verifies against the host-domain JWKS | `verifyOffer` |
| 3 | the signed payload matches the returned offer | `verifyOffer` |
| 4 | `valid_until` is present and fresh | `verifyOffer` |
| 4a | `generated_at` and `valid_until` meet **§5** and **§6**: UTC date-times ending in `Z` that exist, `valid_until` later than `generated_at` and at most 900 seconds after it, `generated_at` at most 60 seconds ahead of `now` | `verifyOffer`, re-checked by `quoteChecks` at the quoting instant |
| 4b | `request.check_in` and `request.check_out` exist, `check_out` is later than `check_in`, `check_in` is not earlier than the day before the UTC date (**§5**, §7); `request.language`, when present, has the form §5 gives | `quoteChecks` |
| 4c | `request.check_in`, `request.check_out` and `request.guests` are the stay you asked for (§7) | `quoteChecks`, from `request` |
| 5 | `availability.available` is true | `quoteChecks` |
| 6 | `price.exact` is true | `quoteChecks` |
| 7 | a direct booking URL is present — and, per **§5.1**, is a node URL (§2): `https`, host the offer's `canonical_domain` or `www.` followed by it, no userinfo, the default port | `quoteChecks` |
| 8 | `agent_permission.may_quote_as_official_direct_offer` is true | `quoteChecks` |
| 9 | the signed `canonical_domain` is the domain the offer was fetched from (§7) | `quoteChecks`, from `domain` |
| 10 | that domain is host-owned (§2): lowercase A-labels, its own registrable domain under the **ICANN section** of the Public Suffix List (the PRIVATE section does not count), not under a brand or closed top-level domain (Specification 13, `booking`, `hotels`); no usable lists = unknown | `quoteChecks`, from `hostOwnedLists` |

| 11 | the discovery document declares `protocol: "vacation-rental-protocol"` and `protocol_version` `"1.0"` or `"0.1"` (§2, §7, 1.0 candidate); no document = unknown | `quoteChecks`, from `discovery` |
| 12 | beyond the §7 list: the signed offer declares `protocol_version` `"1.0"` or `"0.1"` (§5, §9, 1.0 candidate) | `verifyOffer` |

**What remains the caller's responsibility** needs network context this package
deliberately does not have:

- fetching over HTTPS and following a redirect only to a node URL of the
  domain (§2),
- fetching the discovery document, and checking that its `canonical_domain`
  is the domain it was fetched from. What it declares as `protocol` and
  `protocol_version` the gate reads from the document you pass in.

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
| `evaluatedAt`         | the instant the lifetime was judged at (ISO date-time); `null` when the verdict was reached before the clock mattered |
| `reasons`             | every lifetime rule (§5, §6) the signed payload breaks at that instant, in the order of the VRP offer-rules vectors; `[]` when none |

The four statuses:

- **verified** — signature valid, the lifetime meets §5 and §6, **and** the
  offer is still fresh.
- **expired** — signature valid and lifetime well-formed, but `valid_until`
  has passed.
- **invalid** — the presented **artifact** fails verification: a signature is
  present and does not verify, the envelope is tampered/malformed, or the
  signed lifetime breaks a rule a node MUST keep (`lifetime_not_positive`,
  `lifetime_too_long`, `generated_at_in_future`). This is a statement about
  the envelope — per spec §9 a failed check leaves every value inside
  *Unknown*, so nothing in it may be cited as true **or** false.
- **unverifiable** — a verdict could not be reached: the signing key is absent
  from the JWKS or unusable, or `generated_at` / `valid_until` is missing or
  not a UTC date-time ending in `Z` so the lifetime cannot be determined
  (`generated_at_unusable`, `valid_until_unusable`), or `now` itself is not a
  usable date (`clock_unusable`). This is **never** reported as `invalid`,
  because absence of a key is not proof of forgery.

`status: "verified"` alone is **not** permission to quote — it is the crypto
verdict. `safeToQuote()` / `quoteChecks()` layer the §7/§5.1 policy conditions on
top; `quoteChecks()` names each failed condition
(`availability_not_true`, `price_not_exact`, `booking_url_missing`,
`booking_url_invalid`, `booking_url_host_mismatch`,
`quote_permission_not_granted`, `domain_unknown`, `host_owned_unknown`,
`offer_domain_mismatch`, `malformed_domain`, `public_suffix`, `not_host_owned`,
`closed_tld`, `request_missing`, `invalid_check_in`, `invalid_check_out`,
`check_out_not_after_check_in`, `check_in_in_past`, `invalid_language`,
`asked_stay_unknown`, `request_mismatch`, a lifetime code such as `expired`
when quoting later than verifying, `clock_unusable`, or `not_verified`). The host-domain codes are the ones the VRP
host-domain conformance vectors use, the offer-rules codes are the ones the VRP
offer-rules conformance vectors use, and `checkHostOwned(domain, lists)` and
`checkOfferRules(payload, { now, asked })` are exported for checking a domain,
or a payload's lifetime and stay, on their own.

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
- The algorithm is **pinned to Ed25519** under its two registered names,
  `Ed25519` and `EdDSA`. A JWS declaring any other `alg` is rejected as a
  downgrade attempt.
- The **key names the algorithm too** (§3): a key in the JWKS whose own `alg`
  is not exactly `Ed25519` or `EdDSA`, or that has none, is not a VRP signing
  key and is never used, even when its `kid` matches and its curve fits.
- The signature is verified over the **exact received bytes** — no
  canonicalization step to disagree on.
- A valid signature over a payload that disagrees with a plaintext
  `envelope.offer` is treated as tampering (`invalid`).
- **Only the signed payload speaks.** `valid_until`, `generated_at`,
  `availability`, `price`, `booking`, `agent_permission` and `request` are read
  from the verified payload and nowhere else; a member missing there is
  missing, whatever an unsigned part of the envelope says.
- **The lifetime is bounded** (§5, §6): a window longer than 900 seconds, one
  that starts more than 60 seconds in the future, one that runs backwards, or
  one whose instants are not UTC date-times ending in `Z` is never `verified`,
  however valid the signature.
- **The stay is the stay you asked for** (§7): a genuine, fresh, correctly
  signed offer for other dates or another guest count fails the gate, and so
  does a gate call that does not say what was asked for.
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
for the signed offer, and the booking-URL node URLs), and `checkOfferRules`,
`verifyOffer` and `quoteChecks` against a byte-identical copy of the VRP
offer-rules vectors (the lifetime, the clock, the dates, the language tag and
the stay asked for), each re-signed with the conformance test key so the rules,
not the signature, decide. For the VRP 1.0 candidate it runs against
byte-identical copies of the candidate's offer vectors 06 to 15 and its
discovery-version vectors (vrp-spec pull request 187): fifteen discovery
documents and eight pairs of a discovery document and a signed offer. The typed statuses and the quote gate are additional
API surface on top of that contract, covered by their own tests.

## Implement your own

VRP is an open standard. If you are building an independent verifier, the
self-describing conformance vectors and the "get listed" process are documented
in the vrp-spec repository's `IMPLEMENTATIONS.md`.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE). Built entirely
from the public VRP conformance surface; contains no vendor-specific code.
