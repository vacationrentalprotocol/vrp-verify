// Offer rules beyond the signature (VRP spec §5, §6, §7; ADR 0012).
//
// The rules a verifier applies to the signed payload's `generated_at`,
// `valid_until` and `request`, once the signature has been checked:
//   - `generated_at` and `valid_until` are UTC date-times in the schema's
//     form (RFC 3339 `date-time`, ending in Z) that exist in the calendar;
//   - `valid_until` is later than `generated_at` and at most 900 seconds after
//     it, compared as written, fractions of a second included (§5);
//   - `generated_at` is at most 60 seconds ahead of the verifier's clock, and
//     `valid_until` has not passed (§6);
//   - `request.check_in` and `request.check_out` exist in the calendar,
//     `check_out` is later than `check_in`, and `check_in` is not earlier than
//     the day before the verifier's UTC date (§5, §7);
//   - `request.language`, when present, is a language tag of the form §5 gives;
//   - `request.check_in`, `check_out` and `guests` are the stay the agent asked
//     for (§7). A verifier that does not know what was asked for cannot pass
//     this rule (§8: fail closed).
//
// The reason codes and their order are those of the VRP offer-rules
// conformance vectors (vrp-spec examples/conformance/offer-rules/), so a
// result here compares directly with the standard's own check.

export const MAX_LIFETIME_SECONDS = 900;
export const CLOCK_SKEW_SECONDS = 60;
// §5: language subtag (2–3 letters), optional script (4 letters), optional
// region (2 letters or 3 digits). Free text never matches. "(?!\n)" keeps an
// engine whose "$" also matches before a final line break exact.
export const LANGUAGE_TAG = /^[A-Za-z]{2,3}(-[A-Za-z]{4})?(-([A-Za-z]{2}|[0-9]{3}))?$(?!\n)/;

/** Reason codes of the offer rules, in the vectors' vocabulary. */
export const OfferRule = Object.freeze({
  MALFORMED_GENERATED_AT: "malformed_generated_at",
  MALFORMED_VALID_UNTIL: "malformed_valid_until",
  LIFETIME_NOT_POSITIVE: "lifetime_not_positive",
  LIFETIME_TOO_LONG: "lifetime_too_long",
  GENERATED_AT_IN_FUTURE: "generated_at_in_future",
  EXPIRED: "expired",
  REQUEST_MISSING: "request_missing",
  INVALID_CHECK_IN: "invalid_check_in",
  INVALID_CHECK_OUT: "invalid_check_out",
  CHECK_OUT_NOT_AFTER_CHECK_IN: "check_out_not_after_check_in",
  CHECK_IN_IN_PAST: "check_in_in_past",
  INVALID_LANGUAGE: "invalid_language",
  ASKED_STAY_UNKNOWN: "asked_stay_unknown",
  REQUEST_MISMATCH: "request_mismatch",
  // Not a vector reason: the verifier's own clock could not be read, so no
  // rule that depends on it can be judged (§8: fail closed).
  CLOCK_UNUSABLE: "clock_unusable",
});

const DAY_MS = 86400000;

/** A YYYY-MM-DD date that exists in the calendar, as ms at UTC midnight; NaN otherwise. */
export function parseDate(value) {
  const m = typeof value === "string" && /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!m) return NaN;
  // setUTCFullYear, not Date.UTC: Date.UTC reads the years 0–99 as 1900–1999.
  const d = new Date(0);
  d.setUTCFullYear(+m[1], +m[2] - 1, +m[3]);
  const t = d.getTime();
  return d.getUTCFullYear() === +m[1] && d.getUTCMonth() === +m[2] - 1 && d.getUTCDate() === +m[3] ? t : NaN;
}

/** A UTC date-time in the schema's form (ending in Z) that exists, as ms; NaN otherwise. */
export function parseDateTime(value) {
  const m =
    typeof value === "string" && /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z$/.exec(value);
  if (!m) return NaN;
  const d = new Date(0);
  d.setUTCFullYear(+m[1], +m[2] - 1, +m[3]);
  d.setUTCHours(+m[4], +m[5], +m[6], 0);
  const t = d.getTime();
  const exists =
    d.getUTCFullYear() === +m[1] &&
    d.getUTCMonth() === +m[2] - 1 &&
    d.getUTCDate() === +m[3] &&
    d.getUTCHours() === +m[4] &&
    d.getUTCMinutes() === +m[5] &&
    d.getUTCSeconds() === +m[6];
  return exists ? t + (m[7] ? Number(m[7]) * 1000 : 0) : NaN;
}

/**
 * The instant `now` names, as ms: the current time when `now` is omitted
 * (undefined); else a finite number, a valid Date or a parseable string. NaN
 * for anything else (NaN, an Invalid Date, an unparseable string, null), so a
 * caller that passes a broken clock never reads as "now".
 */
export function toClock(now) {
  if (now === undefined) return Date.now();
  if (typeof now === "number") return Number.isFinite(now) ? now : NaN;
  if (now instanceof Date) return now.getTime();
  if (typeof now === "string") {
    const t = Date.parse(now);
    return Number.isFinite(t) ? t : NaN;
  }
  return NaN;
}

/**
 * The lifetime and clock reasons (§5, §6) for `payload` at `clock` (ms), in
 * the vectors' order; an empty list when the lifetime rules are met.
 */
export function lifetimeReasons(payload, clock) {
  const reasons = [];
  const generated = parseDateTime(payload?.generated_at);
  const validUntil = parseDateTime(payload?.valid_until);
  if (Number.isNaN(generated)) reasons.push(OfferRule.MALFORMED_GENERATED_AT);
  if (Number.isNaN(validUntil)) reasons.push(OfferRule.MALFORMED_VALID_UNTIL);
  if (!Number.isNaN(generated) && !Number.isNaN(validUntil)) {
    if (validUntil <= generated) reasons.push(OfferRule.LIFETIME_NOT_POSITIVE);
    else if (validUntil - generated > MAX_LIFETIME_SECONDS * 1000) reasons.push(OfferRule.LIFETIME_TOO_LONG);
  }
  if (!Number.isNaN(generated) && generated > clock + CLOCK_SKEW_SECONDS * 1000) {
    reasons.push(OfferRule.GENERATED_AT_IN_FUTURE);
  }
  if (!Number.isNaN(validUntil) && validUntil <= clock) reasons.push(OfferRule.EXPIRED);
  return reasons;
}

/**
 * The stay rules (§5, §7) for `payload.request` at `clock` (ms) against the
 * stay `asked` for ({ check_in, check_out, guests }, or null/undefined when the
 * verifier does not know it), in the vectors' order; empty when met.
 */
export function requestReasons(payload, clock, asked) {
  const reasons = [];
  const request = payload?.request;
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    reasons.push(OfferRule.REQUEST_MISSING);
    return reasons;
  }
  const checkIn = parseDate(request.check_in);
  const checkOut = parseDate(request.check_out);
  if (Number.isNaN(checkIn)) reasons.push(OfferRule.INVALID_CHECK_IN);
  if (Number.isNaN(checkOut)) reasons.push(OfferRule.INVALID_CHECK_OUT);
  if (!Number.isNaN(checkIn) && !Number.isNaN(checkOut) && checkOut <= checkIn) {
    reasons.push(OfferRule.CHECK_OUT_NOT_AFTER_CHECK_IN);
  }
  // The local date anywhere is at most one day behind the UTC date.
  const dayBefore = Math.floor(clock / DAY_MS) * DAY_MS - DAY_MS;
  if (!Number.isNaN(checkIn) && checkIn < dayBefore) reasons.push(OfferRule.CHECK_IN_IN_PAST);
  if ("language" in request && !(typeof request.language === "string" && LANGUAGE_TAG.test(request.language))) {
    reasons.push(OfferRule.INVALID_LANGUAGE);
  }

  if (!isAskedStay(asked)) reasons.push(OfferRule.ASKED_STAY_UNKNOWN);
  else if (
    request.check_in !== asked.check_in ||
    request.check_out !== asked.check_out ||
    request.guests !== asked.guests
  ) {
    reasons.push(OfferRule.REQUEST_MISMATCH);
  }
  return reasons;
}

/** Whether `asked` names a stay: two date strings and an integer guest count of at least 1. */
export function isAskedStay(asked) {
  return Boolean(
    asked &&
      typeof asked === "object" &&
      !Array.isArray(asked) &&
      typeof asked.check_in === "string" &&
      typeof asked.check_out === "string" &&
      Number.isInteger(asked.guests) &&
      asked.guests >= 1,
  );
}

/**
 * The reasons an offer is not quotable under the offer rules (§5, §6, §7); an
 * empty list when it meets them. `now` is an instant (ms, a Date or a date-time
 * string; omitted: the current time); `asked` is the stay the agent asked for,
 * or null when the verifier does not know it. Same result, same order, as the
 * VRP offer-rules vectors; a `now` that cannot be read gives `clock_unusable`.
 */
export function checkOfferRules(payload, { now, asked } = {}) {
  const clock = toClock(now);
  // Every rule but the forms of the dates depends on the clock; without a
  // usable one nothing can be judged, and an empty list would read as a pass.
  if (!Number.isFinite(clock)) return [OfferRule.CLOCK_UNUSABLE];
  return [...lifetimeReasons(payload, clock), ...requestReasons(payload, clock, asked)];
}
