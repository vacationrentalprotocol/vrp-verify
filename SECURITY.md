# Security Policy

`@vacationrentalprotocol/vrp-verify` is the zero-dependency reference verifier
for VRP (Vacation Rental Protocol) signed verified-stay offers. This policy
covers **this package**: the code in this repository and the npm releases built
from it. Weaknesses in the protocol itself belong to the specification
repository (see below).

## Reporting a vulnerability

Please report privately. Do **not** open a public issue for a suspected
vulnerability.

- **Preferred:** GitHub
  [Report a vulnerability](https://github.com/vacationrentalprotocol/vrp-verify/security/advisories/new)
  (Security → Advisories → Report a vulnerability). This opens a private
  advisory visible only to you and the maintainers.
- **Alternative:** email **security@vacationrentalprotocol.com** with
  `VRP-VERIFY SECURITY` in the subject.

**Protocol-level issues** — a flaw in the VRP specification text, its JSON
schemas, or the published conformance vectors, as opposed to this
implementation of them — should be reported to the specification repository
instead:
[vrp-spec security advisories](https://github.com/vacationrentalprotocol/vrp-spec/security/advisories/new).
If you are unsure which repository is right, report here and we will route it.

Please include, as far as you can:

- the affected function (`verifyOffer`, `safeToQuote`, `quoteChecks`,
  `verifyCompactJws`) and the package version;
- a concrete input — an envelope and a JWKS document — on which the verifier
  returns a verdict it should not: for example `verified` for a forged,
  tampered, or expired offer, or `safeToQuote()` returning `true` for an offer
  that fails a §7 or §4 condition;
- steps to reproduce, ideally as a small vector in the style of
  [`test/vectors/`](./test/vectors/).

The package is maintained by a small team. Reports are handled on a best-effort
basis with **coordinated disclosure**: we will confirm receipt, work with you on
a fix, publish a patched release, and credit you if you wish. There is **no
bug-bounty program**.

## Scope

**In scope** — this verifier:

- **Ed25519 / EdDSA signature verification** over the compact JWS, including
  the `alg` pin: a JWS declaring any algorithm other than `EdDSA` must be
  rejected, never trusted.
- **JWS handling** — header and payload decoding, and the rule that a valid
  signature over a payload that differs from the plaintext `envelope.offer` is
  treated as tampering (`invalid`).
- **JWKS handling** — `kid` lookup and key-shape checks (`kty: "OKP"`,
  `crv: "Ed25519"`), and the rule that an absent or unusable key yields
  `unverifiable`, never `verified`.
- **Freshness** — evaluation of `valid_until` against the injected `now`, and
  the rule that a missing or malformed `valid_until` yields `unverifiable`
  rather than a fresh verdict.
- **Fail-closed behaviour** — any input on which `verifyOffer()` returns
  `verified`, or `safeToQuote()` returns `true`, when a conforming verifier
  must refuse. This includes the offline §7 quote conditions and the §4
  host-pinned `direct_booking_url` check.

**Out of scope** — not this package:

- **The VRP protocol itself.** Specification text, schemas, and conformance
  vectors are maintained in
  [vacationrentalprotocol/vrp-spec](https://github.com/vacationrentalprotocol/vrp-spec);
  report protocol weaknesses there.
- **The HemmaBo product** — its app, booking flows, dashboard, and payment
  behaviour. HemmaBo is one deployment that uses VRP; report product issues to
  HemmaBo directly, not here.
- **The security of an individual host domain** — its DNS, TLS, hosting, and
  server configuration. The protocol's root of trust is domain control; if the
  domain is compromised, no verifier can help.
- **What the caller does around the package** — fetching the JWKS over HTTPS,
  caching and rotation policy, and the three network-dependent §7 conditions
  the README documents as the caller's responsibility.

## Supported versions

Security fixes are released as a new version of the current line on npm.
Earlier releases are not separately maintained; upgrade to the latest release.

## Dependency and supply-chain hygiene

- **Zero runtime dependencies.** `package.json` declares no `dependencies` and
  no `devDependencies`, and there is no lockfile. The verifier uses only the
  Node.js standard library (`node:crypto`).
- **No network access.** The package never fetches a JWKS, a discovery
  document, or anything else; it verifies exactly what you pass in.
- **Least-privilege CI.** Workflows grant `permissions: contents: read`, with
  `security-events: write` added only for CodeQL. Actions are pinned to major
  versions and kept current by Dependabot; CodeQL scans the JavaScript on every
  push and pull request to `main` and on a weekly schedule.
- **Tests run offline** against byte-identical copies of the public VRP
  conformance vectors.

Because the dependency graph is empty, a machine-readable SBOM would list only
this package and Node.js itself; we will generate one in a specific format on
request.
