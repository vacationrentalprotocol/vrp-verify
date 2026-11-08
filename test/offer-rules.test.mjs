// Offer rules beyond the signature (spec §5, §6, §7; ADR 0012), from 0.3.0.
//
// Up to 0.2.0 this package checked only that `valid_until` had not passed: it
// never read `generated_at`, never bounded the lifetime, never checked the
// dates and never compared the signed stay with the stay asked for. These
// tests pin the rules two ways: (1) parity of `checkOfferRules` with the VRP
// offer-rules conformance vectors, copied byte for byte into
// test/offer-rules/vectors.v0.1.json; (2) every vector and a set of isolated
// cases run through the EXPORTED API — verifyOffer, quoteChecks, safeToQuote —
// with the mutated payload re-signed by the public conformance test key, so
// the signature stays valid and the rules, not the crypto, decide.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyOffer,
  quoteChecks,
  safeToQuote,
  checkOfferRules,
  OfferRule,
  QuoteFailure,
  Status,
  Reason,
  MAX_LIFETIME_SECONDS,
  CLOCK_SKEW_SECONDS,
  LANGUAGE_TAG,
} from "../index.js";
import { resignedEnvelope, signOffer, KID } from "./helpers.mjs";

const testDir = dirname(fileURLToPath(import.meta.url));
const base = JSON.parse(readFileSync(join(testDir, "vectors", "01-valid-fresh.json"), "utf8"));
const doc = JSON.parse(readFileSync(join(testDir, "offer-rules", "vectors.v0.1.json"), "utf8"));
const hostDomain = JSON.parse(readFileSync(join(testDir, "host-domain", "vectors.v0.1.json"), "utf8"));

const LISTS = { icannRules: hostDomain.psl_icann_rules, specification13Tlds: hostDomain.icann_specification13_tlds };
const ASKED = { ...base.input.offer.request }; // 2026-09-12 → 2026-09-15, 2 guests
// The gate judges at the quoting instant (default: the current time); the
// base vector's clock keeps these cases deterministic unless a case says otherwise.
const ctx = (request = ASKED, now = base.clock) => ({ domain: "example-host.invalid", hostOwnedLists: LISTS, request, now });
const FUTURE_STAY = { check_in: "2027-03-08", check_out: "2027-03-12", guests: 2 };
const verify = (envelope, now = base.clock) => verifyOffer({ envelope, jwks: base.jwks, now });
const T0 = Date.parse(base.clock); // 2026-06-02T12:05:00Z
const iso = (ms) => new Date(ms).toISOString();

// ---------------------------------------------------------------------------
// The vectors and this package state the same rules

test("the offer-rules vectors state the same constants as this package", () => {
  assert.equal(doc.max_lifetime_seconds, MAX_LIFETIME_SECONDS);
  assert.equal(doc.clock_skew_seconds, CLOCK_SKEW_SECONDS);
  assert.equal(doc.language_tag_pattern, LANGUAGE_TAG.source);
  assert.ok(doc.vectors.length >= 40, `expected the full vector set, found ${doc.vectors.length}`);
});

// (1) Parity: the same reasons, in the same order, as the standard's own check.
for (const v of doc.vectors) {
  test(`offer-rules vector ${v.name}: checkOfferRules matches the vector`, () => {
    assert.deepEqual(checkOfferRules(v.offer, { now: doc.now, asked: v.asked }), v.expected.reasons);
  });
}

// (2) Through the exported API. The base vector's signed offer, with the
// vector's generated_at / valid_until / request in place of its own (absent in
// the vector = absent in the payload), re-signed, verified at the vectors' clock.
function envelopeFor(v) {
  return resignedEnvelope(base, (o) => {
    for (const k of ["generated_at", "valid_until", "request"]) {
      if (k in v.offer) o[k] = structuredClone(v.offer[k]);
      else delete o[k];
    }
  });
}
// This package's older code names for two of the vectors' reasons.
const ALIAS = { malformed_valid_until: Reason.VALID_UNTIL_UNUSABLE, malformed_generated_at: Reason.GENERATED_AT_UNUSABLE };

for (const v of doc.vectors) {
  test(`offer-rules vector ${v.name}: verifyOffer + quoteChecks`, () => {
    const r = verifyOffer({ envelope: envelopeFor(v), jwks: base.jwks, now: doc.now });
    assert.notEqual(r.code, Reason.SIGNATURE_MISMATCH, "the signature is valid; the rules decide");
    const context = ctx(v.asked, doc.now); // null stays null: the verifier does not know the stay
    const q = quoteChecks(r, context);
    const meets = v.expected.reasons.length === 0;
    assert.equal(q.ok, meets, `${v.name}: ${r.status} ${r.code} ${q.failures}`);
    assert.equal(safeToQuote(r, context), meets);
    if (meets) {
      assert.equal(r.status, Status.VERIFIED);
      assert.deepEqual(r.reasons, []);
      assert.deepEqual(q.failures, []);
    } else {
      const seen = new Set([...q.failures, ...r.reasons, r.code, r.status === Status.EXPIRED ? OfferRule.EXPIRED : null]);
      for (const reason of v.expected.reasons) {
        assert.ok(seen.has(reason) || seen.has(ALIAS[reason]), `${v.name}: ${reason} not among ${[...seen]}`);
      }
    }
  });
}

// ---------------------------------------------------------------------------
// Isolated cases: the boundaries, as signed offers

const lifetime = (generatedMs, validUntilMs, now = T0) =>
  verify(resignedEnvelope(base, (o) => { o.generated_at = iso(generatedMs); o.valid_until = iso(validUntilMs); }), now);

test("lifetime of exactly 900 seconds is verified; 900.001 seconds is invalid (lifetime_too_long)", () => {
  const g = T0 - 60_000;
  assert.equal(lifetime(g, g + 900_000).status, Status.VERIFIED);
  const over = lifetime(g, g + 900_001);
  assert.equal(over.status, Status.INVALID);
  assert.equal(over.code, Reason.LIFETIME_TOO_LONG);
  assert.deepEqual(over.reasons, [OfferRule.LIFETIME_TOO_LONG]);
  assert.equal(over.fresh, null);
  assert.deepEqual(quoteChecks(over, ctx()), { ok: false, failures: [QuoteFailure.NOT_VERIFIED] });
});

test("valid_until equal to generated_at, or before it, is invalid (lifetime_not_positive)", () => {
  const g = T0 - 10_000;
  assert.equal(lifetime(g, g).code, Reason.LIFETIME_NOT_POSITIVE);
  assert.equal(lifetime(g, g - 1).code, Reason.LIFETIME_NOT_POSITIVE);
  assert.equal(lifetime(g, g).status, Status.INVALID);
});

test("generated_at 60 seconds ahead of the clock is verified; 60.001 seconds is invalid (generated_at_in_future)", () => {
  assert.equal(lifetime(T0 + 60_000, T0 + 600_000).status, Status.VERIFIED);
  const ahead = lifetime(T0 + 60_001, T0 + 600_000);
  assert.equal(ahead.status, Status.INVALID);
  assert.equal(ahead.code, Reason.GENERATED_AT_IN_FUTURE);
  assert.equal(safeToQuote(ahead, ctx()), false);
});

test("a window that starts a year from now is invalid even though valid_until is far ahead", () => {
  const r = lifetime(T0 + 365 * 86_400_000, T0 + 365 * 86_400_000 + 900_000);
  assert.equal(r.status, Status.INVALID);
  assert.equal(r.code, Reason.GENERATED_AT_IN_FUTURE);
});

test("valid_until equal to now is expired; one millisecond later is fresh", () => {
  const g = T0 - 300_000;
  const atNow = lifetime(g, T0);
  assert.equal(atNow.status, Status.EXPIRED);
  assert.equal(atNow.fresh, false);
  assert.deepEqual(atNow.reasons, [OfferRule.EXPIRED]);
  const later = lifetime(g, T0 + 1);
  assert.equal(later.status, Status.VERIFIED);
  assert.equal(later.fresh, true);
});

test("fractions of a second count, as written (§5)", () => {
  const g = T0 - 60_000;
  const r = verify(resignedEnvelope(base, (o) => {
    o.generated_at = iso(g);
    o.valid_until = iso(g + 900_000).replace(".000Z", ".001Z");
  }));
  assert.equal(r.code, Reason.LIFETIME_TOO_LONG);
});

test("generated_at missing is unverifiable (generated_at_unusable), never verified", () => {
  const r = verify(resignedEnvelope(base, (o) => { delete o.generated_at; }));
  assert.equal(r.status, Status.UNVERIFIABLE);
  assert.equal(r.code, Reason.GENERATED_AT_UNUSABLE);
  assert.equal(safeToQuote(r, ctx()), false);
});

for (const [name, value] of [
  ["an offset instead of Z", "2026-06-02T12:10:00+00:00"],
  ["a date a JavaScript Date would still parse", "Nov 10 2036"],
  ["30 February", "2026-02-30T12:10:00Z"],
  ["hour 24", "2026-06-02T24:00:00Z"],
  ["a number", 1780000000000],
  ["null", null],
]) {
  test(`valid_until that is ${name} is unverifiable (valid_until_unusable)`, () => {
    const r = verify(resignedEnvelope(base, (o) => { o.valid_until = value; }));
    assert.equal(r.status, Status.UNVERIFIABLE);
    assert.equal(r.code, Reason.VALID_UNTIL_UNUSABLE);
    assert.equal(r.fresh, null);
  });
  test(`generated_at that is ${name} is unverifiable (generated_at_unusable)`, () => {
    const r = verify(resignedEnvelope(base, (o) => { o.generated_at = value; }));
    assert.equal(r.status, Status.UNVERIFIABLE);
    assert.equal(r.code, Reason.GENERATED_AT_UNUSABLE);
  });
}

test("an unusable evaluation instant is unverifiable (clock_unusable)", () => {
  const r = verify(base.input, "not a date");
  assert.equal(r.status, Status.UNVERIFIABLE);
  assert.equal(r.code, Reason.CLOCK_UNUSABLE);
  assert.equal(safeToQuote(r, ctx()), false);
});

test("the result says when it was judged and lists every lifetime rule broken", () => {
  const r = verify(base.input);
  assert.equal(r.evaluatedAt, iso(T0));
  assert.deepEqual(r.reasons, []);
  const both = verify(resignedEnvelope(base, (o) => { o.generated_at = T0 + 120_000 && iso(T0 + 120_000); o.valid_until = iso(T0 - 1); }));
  assert.deepEqual(both.reasons, [OfferRule.LIFETIME_NOT_POSITIVE, OfferRule.GENERATED_AT_IN_FUTURE, OfferRule.EXPIRED]);
});

// ---------------------------------------------------------------------------
// The stay asked for (§7) and the dates (§5)

test("without the stay asked for, a valid offer is not safe to quote (asked_stay_unknown)", () => {
  const r = verify(base.input);
  assert.equal(r.status, Status.VERIFIED);
  const { request, ...noRequest } = ctx();
  assert.deepEqual(quoteChecks(r, noRequest), { ok: false, failures: [QuoteFailure.ASKED_STAY_UNKNOWN] });
  assert.equal(safeToQuote(r, noRequest), false);
});

for (const [name, request] of [
  ["null", null],
  ["an array", ["2026-09-12", "2026-09-15", 2]],
  ["guests as a string", { check_in: "2026-09-12", check_out: "2026-09-15", guests: "2" }],
  ["guests zero", { check_in: "2026-09-12", check_out: "2026-09-15", guests: 0 }],
  ["check_in missing", { check_out: "2026-09-15", guests: 2 }],
  ["camelCase keys", { checkIn: "2026-09-12", checkOut: "2026-09-15", guests: 2 }],
]) {
  test(`a request context that is ${name} does not name a stay (asked_stay_unknown)`, () => {
    const q = quoteChecks(verify(base.input), ctx(request));
    assert.deepEqual(q, { ok: false, failures: [QuoteFailure.ASKED_STAY_UNKNOWN] });
  });
}

for (const [name, asked] of [
  ["other dates", { check_in: "2026-12-20", check_out: "2026-12-23", guests: 2 }],
  ["another arrival date", { check_in: "2026-09-11", check_out: "2026-09-15", guests: 2 }],
  ["another departure date", { check_in: "2026-09-12", check_out: "2026-09-16", guests: 2 }],
  ["another guest count", { check_in: "2026-09-12", check_out: "2026-09-15", guests: 4 }],
]) {
  test(`a genuine offer for ${name} is not the offer asked for (request_mismatch)`, () => {
    const r = verify(base.input);
    assert.equal(r.status, Status.VERIFIED, "the signature is valid; the gate decides");
    const q = quoteChecks(r, ctx(asked));
    assert.deepEqual(q, { ok: false, failures: [QuoteFailure.REQUEST_MISMATCH] });
    assert.equal(safeToQuote(r, ctx(asked)), false);
  });
}

test("the stay asked for, signed back, passes; extra node-computed members in request do not matter", () => {
  const r = verify(resignedEnvelope(base, (o) => { o.request = { ...o.request, nights: 3, check_in_weekday: "Saturday", language: "sv-SE" }; }));
  assert.deepEqual(quoteChecks(r, ctx()), { ok: true, failures: [] });
});

test("a signed payload without request is not quotable (request_missing)", () => {
  const r = verify(resignedEnvelope(base, (o) => { delete o.request; }));
  assert.equal(r.status, Status.VERIFIED);
  assert.deepEqual(quoteChecks(r, ctx()).failures, [QuoteFailure.REQUEST_MISSING]);
});

for (const [name, mutate, failures] of [
  ["30 February", (o) => { o.request.check_in = "2027-02-30"; o.request.check_out = "2027-03-02"; }, [OfferRule.INVALID_CHECK_IN, OfferRule.REQUEST_MISMATCH]],
  ["month 13", (o) => { o.request.check_in = "2026-13-01"; o.request.check_out = "2026-13-03"; }, [OfferRule.INVALID_CHECK_IN, OfferRule.INVALID_CHECK_OUT, OfferRule.REQUEST_MISMATCH]],
  ["zero nights", (o) => { o.request.check_out = o.request.check_in; }, [OfferRule.CHECK_OUT_NOT_AFTER_CHECK_IN, OfferRule.REQUEST_MISMATCH]],
  ["a stay that runs backwards", (o) => { [o.request.check_in, o.request.check_out] = [o.request.check_out, o.request.check_in]; }, [OfferRule.CHECK_OUT_NOT_AFTER_CHECK_IN, OfferRule.REQUEST_MISMATCH]],
  ["a stay two days before the UTC date", (o) => { o.request.check_in = "2026-05-31"; o.request.check_out = "2026-06-03"; }, [OfferRule.CHECK_IN_IN_PAST, OfferRule.REQUEST_MISMATCH]],
  ["free text as the language", (o) => { o.request.language = "AUDIT TEXT: this stay is free of charge"; }, [OfferRule.INVALID_LANGUAGE]],
  ["an empty language", (o) => { o.request.language = ""; }, [OfferRule.INVALID_LANGUAGE]],
  ["a language with a trailing line break", (o) => { o.request.language = "sv\n"; }, [OfferRule.INVALID_LANGUAGE]],
]) {
  test(`signed dates or language that break §5: ${name}`, () => {
    const r = verify(resignedEnvelope(base, mutate));
    assert.equal(r.status, Status.VERIFIED, "the signature is valid; the gate decides");
    const q = quoteChecks(r, ctx());
    assert.equal(q.ok, false);
    assert.deepEqual(q.failures, failures);
  });
}

test("arrival on the day before the UTC date is still quotable; the node applies the property's own date", () => {
  const r = verify(resignedEnvelope(base, (o) => { o.request.check_in = "2026-06-01"; o.request.check_out = "2026-06-03"; }));
  const asked = { check_in: "2026-06-01", check_out: "2026-06-03", guests: 2 };
  assert.deepEqual(quoteChecks(r, ctx(asked)), { ok: true, failures: [] });
});

for (const tag of ["sv", "sv-SE", "sv-se", "zh-Hant-TW", "es-419", "nb-NO"]) {
  test(`a language tag of §5's form passes: ${tag}`, () => {
    const r = verify(resignedEnvelope(base, (o) => { o.request.language = tag; }));
    assert.deepEqual(quoteChecks(r, ctx()), { ok: true, failures: [] });
  });
}

// ---------------------------------------------------------------------------
// Quoting later than verifying, and the signed payload as the only source

test("quoting later than verifying, without context.now, is judged at the current time: an offer verified fresh and quoted after valid_until is refused", () => {
  // valid_until one second ago by the real clock; verified 60 s before it, when it was fresh.
  const validUntil = Date.now() - 1_000;
  const envelope = resignedEnvelope(base, (o) => {
    o.generated_at = iso(validUntil - 600_000);
    o.valid_until = iso(validUntil);
    o.request = { ...FUTURE_STAY };
  });
  const r = verify(envelope, validUntil - 60_000);
  assert.equal(r.status, Status.VERIFIED, "fresh when verified");
  const { now, ...withoutNow } = ctx(FUTURE_STAY);
  const later = quoteChecks(r, withoutNow);
  assert.equal(later.ok, false);
  assert.deepEqual(later.failures, [QuoteFailure.EXPIRED]);
  assert.equal(safeToQuote(r, withoutNow), false);
  // The same gate at the verification instant, stated explicitly, passes.
  assert.deepEqual(quoteChecks(r, ctx(FUTURE_STAY, validUntil - 60_000)), { ok: true, failures: [] });
});

test("without context.now, a fresh offer for a future stay passes at the current time", () => {
  const r = verify(resignedEnvelope(base, (o) => {
    o.generated_at = iso(Date.now() - 1_000);
    o.valid_until = iso(Date.now() + 600_000);
    o.request = { ...FUTURE_STAY };
  }), Date.now());
  const { now, ...withoutNow } = ctx(FUTURE_STAY);
  assert.deepEqual(quoteChecks(r, withoutNow), { ok: true, failures: [] });
});

for (const [name, now] of [["NaN", NaN], ["an unparseable string", "not a date"], ["an Invalid Date", new Date("not a date")], ["null", null], ["Infinity", Infinity], ["an object", {}]]) {
  test(`checkOfferRules fails closed with clock_unusable when now is ${name}`, () => {
    assert.deepEqual(checkOfferRules(base.input.offer, { now, asked: ASKED }), [OfferRule.CLOCK_UNUSABLE]);
  });
  test(`quoteChecks fails closed with clock_unusable when context.now is ${name}`, () => {
    const r = verify(base.input);
    assert.equal(r.status, Status.VERIFIED);
    assert.deepEqual(quoteChecks(r, ctx(ASKED, now)), { ok: false, failures: [QuoteFailure.CLOCK_UNUSABLE] });
  });
  test(`verifyOffer is unverifiable with clock_unusable when now is ${name}`, () => {
    const r = verifyOffer({ envelope: base.input, jwks: base.jwks, now });
    assert.equal(r.status, Status.UNVERIFIABLE);
    assert.equal(r.code, Reason.CLOCK_UNUSABLE);
  });
}

test("checkOfferRules without now judges at the current time", () => {
  const payload = { generated_at: iso(Date.now() - 1_000), valid_until: iso(Date.now() + 600_000), request: { ...FUTURE_STAY } };
  assert.deepEqual(checkOfferRules(payload, { asked: FUTURE_STAY }), []);
  assert.deepEqual(checkOfferRules({ ...payload, valid_until: iso(Date.now() - 1) }, { asked: FUTURE_STAY }), [OfferRule.EXPIRED]);
});

test("an offer verified fresh but quoted after valid_until fails the gate (expired)", () => {
  const r = verify(base.input); // fresh at the base clock
  assert.equal(r.status, Status.VERIFIED);
  const validUntil = Date.parse(base.input.offer.valid_until);
  assert.deepEqual(quoteChecks(r, ctx(ASKED, validUntil)), { ok: false, failures: [QuoteFailure.EXPIRED] });
  assert.deepEqual(quoteChecks(r, ctx(ASKED, validUntil - 1)), { ok: true, failures: [] });
});

test("values outside the signed payload never count: unsigned envelope members do not supply a missing price.exact, availability or permission", () => {
  const envelope = resignedEnvelope(base, (o) => {
    delete o.price.exact;
    delete o.availability;
    delete o.agent_permission;
  });
  // The same members, present and true, OUTSIDE the signed payload.
  envelope.price = { ...base.input.offer.price, exact: true };
  envelope.availability = { available: true };
  envelope.agent_permission = { may_quote_as_official_direct_offer: true };
  envelope.valid_until = base.input.offer.valid_until;
  const r = verify(envelope);
  assert.equal(r.status, Status.VERIFIED);
  const q = quoteChecks(r, ctx());
  assert.equal(q.ok, false);
  for (const f of [QuoteFailure.AVAILABILITY_NOT_TRUE, QuoteFailure.PRICE_NOT_EXACT, QuoteFailure.QUOTE_PERMISSION_NOT_GRANTED]) {
    assert.ok(q.failures.includes(f), `${f} expected in ${q.failures}`);
  }
});

test("an amount is not exactness: price.exact missing, false or a string fails even with a signed total", () => {
  for (const exact of [undefined, false, "true", 1]) {
    const r = verify(resignedEnvelope(base, (o) => {
      if (exact === undefined) delete o.price.exact; else o.price.exact = exact;
      o.price.public_total = 123400;
    }));
    assert.equal(r.status, Status.VERIFIED);
    assert.ok(quoteChecks(r, ctx()).failures.includes(QuoteFailure.PRICE_NOT_EXACT), String(exact));
  }
});

test("a plaintext envelope.offer that contradicts the signed payload is tampering (payload_offer_mismatch), not a quote", () => {
  const envelope = resignedEnvelope(base, (o) => { o.price.exact = false; });
  envelope.offer = structuredClone(envelope.offer);
  envelope.offer.price.exact = true; // the visible offer says exact; the signed bytes say not
  const r = verify(envelope);
  assert.equal(r.status, Status.INVALID);
  assert.equal(r.code, Reason.PAYLOAD_OFFER_MISMATCH);
  assert.equal(safeToQuote(r, ctx()), false);
});

test("a bare JWS (no envelope) is judged by the same rules", () => {
  const offer = structuredClone(base.input.offer);
  offer.generated_at = iso(T0 - 1000);
  offer.valid_until = iso(T0 + 1_000_000);
  const r = verifyOffer({ jws: signOffer(offer, { kid: KID }), jwks: base.jwks, now: base.clock });
  assert.equal(r.status, Status.INVALID);
  assert.equal(r.code, Reason.LIFETIME_TOO_LONG);
});

test("the valid vector still passes the whole gate (nothing valid became invalid)", () => {
  const r = verify(base.input);
  assert.equal(r.status, Status.VERIFIED);
  assert.equal(r.fresh, true);
  assert.deepEqual(quoteChecks(r, ctx()), { ok: true, failures: [] });
  assert.equal(safeToQuote(r, ctx()), true);
});
