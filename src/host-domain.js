// Host-owned domain (VRP spec §2) and offer binding (§7).
//
// A VRP node is a domain registered for the host, never a name under another
// party's domain. `canonical_domain` MUST:
//   1. be lowercase ASCII, internationalized labels in A-label (`xn--`) form,
//      no trailing dot;
//   2. equal its own registrable domain under the Public Suffix List algorithm,
//      using ONLY the rules in the list's ICANN section, each rule compared in
//      A-label form (default rule `*` when no ICANN rule matches). The PRIVATE
//      section does not count: it lists domains under which a company hands
//      out names to its customers;
//   3. not sit under a brand or closed top-level domain: every TLD with
//      `"specification13": true` in ICANN's gTLD list, plus `booking` and
//      `hotels` (this list changes only by ADR).
// A verifier that holds no copy of the ICANN section or of ICANN's gTLD list
// MUST treat the node as unknown (§9).
//
// This package does no network I/O. The caller fetches both lists from their
// publishers (PSL_URL, GTLDS_URL), with its own caching, and passes them in;
// icannRulesFromPsl() and specification13FromGtlds() turn the raw documents
// into the shape checkHostOwned() reads.

import { domainToASCII } from "node:url";

/** The Public Suffix List, as published. */
export const PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat";

/** ICANN's gTLD list, whose entries carry `specification13`. */
export const GTLDS_URL = "https://www.icann.org/resources/registries/gtlds/v2/gtlds.json";

/** §2: closed top-level domains named in the spec beyond Specification 13. Changed only by ADR. */
export const CLOSED_TLDS = Object.freeze(["booking", "hotels"]);

/** Reason codes, identical to the vrp-spec host-domain conformance vectors. */
export const HostDomainReason = Object.freeze({
  MALFORMED_DOMAIN: "malformed_domain",
  PUBLIC_SUFFIX: "public_suffix",
  NOT_HOST_OWNED: "not_host_owned",
  CLOSED_TLD: "closed_tld",
});

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

// A rule label in A-label form; "*" stays a wildcard.
const toALabel = (label) => (label === "*" ? label : domainToASCII(label));

// Public Suffix List algorithm (https://publicsuffix.org/list/): the prevailing
// rule is an exception rule if one matches, else the matching rule with the
// most labels, else the default rule "*". Returns the suffix's label count.
function publicSuffixLength(labels, rules) {
  let exceptionLength = null;
  let longest = 1;
  for (const raw of rules) {
    if (typeof raw !== "string" || raw.length === 0) continue;
    const exception = raw.startsWith("!");
    const rule = (exception ? raw.slice(1) : raw).split(".").map(toALabel);
    if (rule.length > labels.length) continue;
    const offset = labels.length - rule.length;
    if (!rule.every((l, i) => l === "*" || l === labels[offset + i])) continue;
    if (exception) exceptionLength = rule.length - 1;
    else if (rule.length > longest) longest = rule.length;
  }
  return exceptionLength !== null ? exceptionLength : longest;
}

/**
 * The registrable domain of `host` under `rules` (ICANN-section rules only),
 * or null when `host` is itself a public suffix.
 */
export function registrableDomain(host, rules) {
  const labels = host.split(".");
  const suffix = publicSuffixLength(labels, rules);
  return labels.length > suffix ? labels.slice(-(suffix + 1)).join(".") : null;
}

/** True when `lists` has the shape checkHostOwned() needs. */
export function isHostOwnedLists(lists) {
  return (
    lists !== null &&
    typeof lists === "object" &&
    Array.isArray(lists.icannRules) &&
    lists.icannRules.length > 0 &&
    Array.isArray(lists.specification13Tlds) &&
    // ICANN's list has always marked brand TLDs; an empty set means the list
    // was not read as intended, and would let every brand TLD through.
    lists.specification13Tlds.length > 0
  );
}

/**
 * §2: is `domain` a host-owned domain? Returns null when it is, otherwise a
 * HostDomainReason code. Throws TypeError when `lists` is not a lists object,
 * so a missing list can never read as a pass.
 *
 * @param {string} domain  the `canonical_domain` to check, exactly as signed
 * @param {{ icannRules: string[], specification13Tlds: string[] }} lists
 */
export function checkHostOwned(domain, lists) {
  if (!isHostOwnedLists(lists)) {
    throw new TypeError("checkHostOwned: lists must be { icannRules: string[], specification13Tlds: string[] }, both non-empty");
  }
  if (typeof domain !== "string" || domain.length === 0 || domain.length > 253) {
    return HostDomainReason.MALFORMED_DOMAIN;
  }
  const labels = domain.split(".");
  if (!labels.every((l) => LABEL.test(l))) return HostDomainReason.MALFORMED_DOMAIN;
  const registrable = registrableDomain(domain, lists.icannRules);
  if (registrable === null) return HostDomainReason.PUBLIC_SUFFIX;
  if (registrable !== domain) return HostDomainReason.NOT_HOST_OWNED;
  const tld = labels[labels.length - 1];
  if (lists.specification13Tlds.includes(tld) || CLOSED_TLDS.includes(tld)) {
    return HostDomainReason.CLOSED_TLD;
  }
  return null;
}

/**
 * The rules of the ICANN section of a Public Suffix List document (the text
 * served at PSL_URL), or null when the section markers are missing or the
 * section is empty. Comments and blank lines are dropped.
 *
 * @param {string} text
 * @returns {string[] | null}
 */
export function icannRulesFromPsl(text) {
  if (typeof text !== "string") return null;
  const lines = text.split("\n");
  const begin = lines.findIndex((l) => l.includes("===BEGIN ICANN DOMAINS==="));
  const end = lines.findIndex((l) => l.includes("===END ICANN DOMAINS==="));
  if (begin < 0 || end <= begin) return null;
  const rules = lines
    .slice(begin + 1, end)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("//"));
  return rules.length > 0 ? rules : null;
}

/**
 * The top-level domains marked `"specification13": true` in ICANN's gTLD list
 * (the JSON served at GTLDS_URL, already parsed), or null when the document
 * does not have the expected shape or marks no top-level domain at all (a
 * renamed field would otherwise read as "no brand TLDs" and let them pass).
 *
 * @param {unknown} json
 * @returns {string[] | null}
 */
export function specification13FromGtlds(json) {
  const gtlds = json && typeof json === "object" ? json.gTLDs : null;
  if (!Array.isArray(gtlds) || gtlds.length === 0) return null;
  const tlds = gtlds
    .filter((g) => g && g.specification13 === true && typeof g.gTLD === "string")
    .map((g) => g.gTLD);
  return tlds.length > 0 ? tlds : null;
}

/**
 * The domain a caller says it fetched the offer from, as the host of the URL
 * it requested (lowercased, IDNs in A-label form), or null when it is not a
 * bare host name.
 *
 * @param {unknown} domain
 * @returns {string | null}
 */
export function fetchedHost(domain) {
  if (typeof domain !== "string" || domain.length === 0) return null;
  // A bare host: no scheme, path, port, userinfo, query, fragment or space.
  if (/[/:@?#\s\\]/.test(domain)) return null;
  try {
    const host = new URL(`https://${domain}`).hostname;
    return host.length > 0 ? host : null;
  } catch {
    return null;
  }
}
