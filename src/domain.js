// Host-owned domain, node URLs and offer binding (VRP v0.1 §2, §5.1, §7;
// vrp-spec ADR 0009).
//
// A VRP node is a domain registered for the host, never a name under another
// party's domain:
//   - lowercase ASCII A-labels, no trailing dot;
//   - its own registrable domain under the ICANN section of the Public Suffix
//     List, rules compared in A-label form (the PRIVATE section does not count);
//   - not under a brand or closed top-level domain: Specification 13 in ICANN's
//     gTLD list, or one the standard names.
// This package has no network access: the caller supplies both lists. Without
// them the result is unknown, never a pass. `icannRulesFromPsl` and
// `specification13TldsFromGtlds` turn the published files into that input.

import { domainToASCII } from "node:url";

/** spec/v0.1.md §2: closed top-level domains the standard names. */
export const CLOSED_TLDS = Object.freeze(["booking", "hotels"]);

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

// A rule label in A-label form; "*" stays a wildcard.
const toALabel = (label) => (label === "*" ? label : domainToASCII(label));

/** The rules between ===BEGIN ICANN DOMAINS=== and ===END ICANN DOMAINS=== of public_suffix_list.dat. */
export function icannRulesFromPsl(text) {
  const lines = String(text).split("\n");
  const begin = lines.findIndex((l) => l.includes("===BEGIN ICANN DOMAINS==="));
  const end = lines.findIndex((l) => l.includes("===END ICANN DOMAINS==="));
  if (begin < 0 || end < begin) throw new Error("ICANN section not found in the Public Suffix List");
  return lines
    .slice(begin + 1, end)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("//"));
}

/** The top-level domains ICANN's gtlds.json marks `"specification13": true`. */
export function specification13TldsFromGtlds(doc) {
  return (doc?.gTLDs ?? []).filter((g) => g.specification13 === true).map((g) => g.gTLD);
}

// Public Suffix List algorithm: an exception rule if one matches, else the
// matching rule with the most labels, else the default rule "*".
function publicSuffixLength(labels, rules) {
  let exception = null;
  let longest = 1;
  for (const raw of rules) {
    const isException = raw.startsWith("!");
    const rule = (isException ? raw.slice(1) : raw).split(".").map(toALabel);
    if (rule.length > labels.length) continue;
    const offset = labels.length - rule.length;
    if (!rule.every((l, i) => l === "*" || l === labels[offset + i])) continue;
    if (isException) exception = rule.length - 1;
    else longest = Math.max(longest, rule.length);
  }
  return exception ?? longest;
}

/** The registrable domain of `host` under `rules`, or null when `host` is a public suffix. */
export function registrableDomain(host, rules) {
  const labels = host.split(".");
  const suffix = publicSuffixLength(labels, rules);
  return labels.length > suffix ? labels.slice(-(suffix + 1)).join(".") : null;
}

/**
 * §2. Returns null when `domain` is a host-owned domain, else one of
 * "lists_unavailable", "malformed_domain", "public_suffix", "not_host_owned",
 * "closed_tld".
 */
export function checkHostOwned(domain, lists) {
  if (typeof domain !== "string" || domain.length === 0 || domain.length > 253) return "malformed_domain";
  const labels = domain.split(".");
  if (!labels.every((l) => LABEL.test(l))) return "malformed_domain";
  if (!lists || !Array.isArray(lists.icannRules) || !Array.isArray(lists.specification13Tlds)) {
    return "lists_unavailable";
  }
  const registrable = registrableDomain(domain, lists.icannRules);
  if (registrable === null) return "public_suffix";
  if (registrable !== domain) return "not_host_owned";
  const tld = labels[labels.length - 1];
  if (lists.specification13Tlds.includes(tld) || CLOSED_TLDS.includes(tld)) return "closed_tld";
  return null;
}

/**
 * §2, §5.1: an https URL whose host is `canonicalDomain` or `www.` + it, with no
 * userinfo and no port other than the https default. Returns null when it is,
 * else one of "url_invalid", "url_not_https", "url_userinfo", "url_port",
 * "url_host_mismatch".
 */
export function checkNodeUrl(url, canonicalDomain) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return "url_invalid";
  }
  if (parsed.protocol !== "https:") return "url_not_https";
  if (parsed.username !== "" || parsed.password !== "") return "url_userinfo";
  if (parsed.port !== "") return "url_port";
  const host = parsed.hostname;
  return host === canonicalDomain || host === `www.${canonicalDomain}` ? null : "url_host_mismatch";
}

/**
 * §2: for a caller that follows redirects while fetching a node resource, every
 * redirect target is itself a node URL. Returns null, "redirect_not_https" or
 * "redirect_off_node".
 */
export function checkRedirects(chain, canonicalDomain) {
  for (const location of chain ?? []) {
    const reason = checkNodeUrl(location, canonicalDomain);
    if (reason === "url_not_https") return "redirect_not_https";
    if (reason) return "redirect_off_node";
  }
  return null;
}

/**
 * §2, §7: the discovery document fetched from `fetchedDomain`. Returns the
 * failed conditions as a list of codes (empty when it passes): "protocol",
 * "protocol_version", "discovery_domain_mismatch", "jwks_url_not_node_url",
 * "offer_endpoint_not_node_url".
 */
export function discoveryChecks(discovery, { fetchedDomain } = {}) {
  const failures = [];
  const d = discovery && typeof discovery === "object" ? discovery : {};
  if (d.protocol !== "vacation-rental-protocol") failures.push("protocol");
  if (d.protocol_version !== "0.1") failures.push("protocol_version");
  if (typeof fetchedDomain !== "string" || d.canonical_domain !== fetchedDomain) {
    failures.push("discovery_domain_mismatch");
  }
  if (checkNodeUrl(d.jwks_url, fetchedDomain) !== null) failures.push("jwks_url_not_node_url");
  if (checkNodeUrl(d.verified_stay_offer_endpoint, fetchedDomain) !== null) {
    failures.push("offer_endpoint_not_node_url");
  }
  return failures;
}
