import { test } from "node:test";
import assert from "node:assert/strict";

import { memoryAdapter } from "better-auth/adapters/memory";

import { checkStoreConformance } from "../src/testing/conformance.ts";
import {
    affectedRows,
    createBetterAuthStore,
    DEFAULT_MODEL,
    type BetterAuthAdapterLike,
} from "../src/better-auth/store.ts";
import { otplinkSchema } from "../src/better-auth/schema.ts";
import { otplink } from "../src/better-auth/plugin.ts";
import { object, optional, record, string } from "../src/better-auth/validate.ts";
import { SECRET, BASE_URL } from "./helpers.ts";

/**
 * Builds a store over a genuine Better Auth adapter.
 *
 * Deliberately not a hand-written double. The whole risk this store carries
 * is that Better Auth's `Where` and `updateMany` behave differently from the
 * SQL the rest of the package emits, and a double written from the same
 * assumptions as the store would agree with those assumptions and prove
 * nothing. `memoryAdapter` runs the real `createAdapterFactory` pipeline —
 * the same where-clause transformation, field mapping, and input transforms
 * every other adapter goes through.
 */
function betterAuthStore() {
    const plugin = otplink({
        secret: SECRET,
        baseUrl: BASE_URL,
        mailer: async () => {},
    });

    const db: Record<string, unknown[]> = { [DEFAULT_MODEL]: [] };
    const adapter = memoryAdapter(db)({
        plugins: [plugin],
    } as never) as unknown as BetterAuthAdapterLike;

    return createBetterAuthStore({ adapter });
}

test("the Better Auth store satisfies the conformance suite", async () => {
    const report = await checkStoreConformance({ createStore: betterAuthStore });
    assert.ok(report.passed, report.summary);
    // The concurrency check is the one that matters most here: it is what
    // proves the guarded `updateMany` elects a single winner rather than the
    // read-then-write race a naive adapter-backed store would have.
    assert.ok(report.results.length >= 15);
});

test("attempts are modelled as a countdown the adapter can actually guard on", async () => {
    // Better Auth's `Where` compares a field to a literal and never to
    // another field, so `attempts < maxAttempts` is inexpressible. This is
    // the substitution that makes the guard possible, and the public shape
    // has to survive it.
    const store = betterAuthStore();
    const now = 1_700_000_000_000;

    await store.insert({
        id: "ch_countdown",
        email: "person@example.com",
        purpose: "sign-in",
        codeHash: "code_countdown",
        tokenHash: "token_countdown",
        bindingHash: null,
        metadata: null,
        attempts: 1,
        maxAttempts: 4,
        createdAt: now,
        expiresAt: now + 900_000,
        consumedAt: null,
    });

    const outcome = await store.registerFailedAttempt({
        email: "person@example.com",
        purpose: "sign-in",
        now: now + 1,
    });
    assert.equal(outcome.found, true);
    assert.equal(outcome.remaining, 2, "one attempt of the remaining three was spent");

    const claimed = await store.consume({
        by: "token",
        tokenHash: "token_countdown",
        now: now + 2,
    });
    assert.ok(claimed);
    assert.equal(claimed.attempts, 2, "attempts is reported counting up, as the interface says");
    assert.equal(claimed.maxAttempts, 4);
});

test("concurrent failed attempts each spend exactly one try", async () => {
    // A read-then-write decrement loses updates under concurrency, and every
    // lost decrement is a free brute-force guess. The compare-and-set retry
    // loop exists precisely to stop that.
    const store = betterAuthStore();
    const now = 1_700_000_000_000;

    await store.insert({
        id: "ch_race",
        email: "race@example.com",
        purpose: "sign-in",
        codeHash: "code_race",
        tokenHash: "token_race",
        bindingHash: null,
        metadata: null,
        attempts: 0,
        maxAttempts: 8,
        createdAt: now,
        expiresAt: now + 900_000,
        consumedAt: null,
    });

    await Promise.all(
        Array.from({ length: 5 }, () =>
            store.registerFailedAttempt({
                email: "race@example.com",
                purpose: "sign-in",
                now: now + 1,
            }),
        ),
    );

    const claimed = await store.consume({ by: "token", tokenHash: "token_race", now: now + 2 });
    assert.ok(claimed, "three attempts should still remain");
    assert.equal(claimed.attempts, 5, "all five concurrent attempts were counted");
});

test("a spent challenge stays present so the user is told the right thing", async () => {
    const store = betterAuthStore();
    const now = 1_700_000_000_000;

    await store.insert({
        id: "ch_spent",
        email: "spent@example.com",
        purpose: "sign-in",
        codeHash: "code_spent",
        tokenHash: "token_spent",
        bindingHash: null,
        metadata: null,
        attempts: 0,
        maxAttempts: 1,
        createdAt: now,
        expiresAt: now + 900_000,
        consumedAt: null,
    });

    const first = await store.registerFailedAttempt({
        email: "spent@example.com",
        purpose: "sign-in",
        now: now + 1,
    });
    assert.deepEqual(first, { found: true, remaining: 0 });

    // Reporting `found: false` here would turn "no attempts left" into "wrong
    // code" on every submission after the last one, looping the user forever.
    const second = await store.registerFailedAttempt({
        email: "spent@example.com",
        purpose: "sign-in",
        now: now + 2,
    });
    assert.deepEqual(second, { found: true, remaining: 0 });
});

test("affectedRows reads every driver shape, and refuses to guess", () => {
    // Better Auth types `updateMany` as `Promise<number>` and current versions
    // deliver one, but through 1.6.2 — inside this package's supported peer
    // range — the Drizzle adapter returned the raw driver result and the
    // memory adapter returned the updated record. The single-use guarantee
    // depends on reading all of them correctly.
    assert.equal(affectedRows(1), 1, "a conforming adapter");
    assert.equal(affectedRows(0), 0);
    assert.equal(affectedRows(2n), 2);

    assert.equal(affectedRows({ rowCount: 1 }), 1, "node-postgres, neon");
    assert.equal(affectedRows({ rowsAffected: 1 }), 1, "planetscale, libSQL, D1 binding");
    assert.equal(affectedRows({ changes: 1 }), 1, "better-sqlite3, node:sqlite");
    assert.equal(affectedRows({ changes: 0 }), 0, "a guard that matched nothing");
    assert.equal(affectedRows({ numUpdatedRows: 1n }), 1, "Kysely raw");
    assert.equal(affectedRows({ meta: { changes: 1 } }), 1, "Cloudflare D1 nests it");
    assert.equal(affectedRows({ meta: { changes: 0 } }), 0);

    // mysql2 returns a one-element [ResultSetHeader] tuple whose length is 1
    // no matter how many rows matched. Measuring the array would report a
    // successful claim for an update that changed nothing — a losing racer
    // would conclude it had won and a consumed challenge would redeem twice.
    assert.equal(affectedRows([{ affectedRows: 1 }]), 1, "mysql2 matched one row");
    assert.equal(affectedRows([{ affectedRows: 0 }]), 0, "mysql2 matched nothing");

    // postgres-js and bun-sql return an Array subclass carrying `count`. On a
    // non-returning write its length is 0 while `count` holds the truth, so
    // `count` has to win over the array fallback.
    const postgresJs = Object.assign([], { count: 1 });
    assert.equal(affectedRows(postgresJs), 1, "postgres-js counts without returning rows");
    assert.equal(affectedRows(Object.assign([], { count: 0 })), 0);

    // A plain array of returned rows is still measured by length.
    assert.equal(affectedRows([{ id: "a" }, { id: "b" }]), 2);
    assert.equal(affectedRows([]), 0);

    // The memory adapter through 1.6.2 handed back the row itself. Recognized
    // by the column only otplink writes, and sound only because every guarded
    // update in the store targets a unique key.
    assert.equal(affectedRows({ challengeId: "ch_1", email: "a@b.c" }), 1);
    assert.equal(affectedRows(null), 0, "the memory adapter's miss");
    assert.equal(affectedRows(undefined), 0);

    // Zero is a real answer meaning "you did not win". Returning it for a
    // result we cannot read would present a broken adapter as an expired link
    // to every user forever, so an unreadable shape is an error instead.
    assert.throws(() => affectedRows({}), /affected-row count/);
    assert.throws(() => affectedRows({ someUnrelatedKey: true }), /affected-row count/);
    assert.throws(() => affectedRows("1"), /affected-row count/);
    assert.throws(() => affectedRows(Number.NaN), /non-finite/);
});

test("the schema declares the constraints the design depends on", () => {
    const schema = otplinkSchema();
    const fields = schema[DEFAULT_MODEL]!.fields;

    // A token collision must fail loudly at insert rather than silently
    // overwrite a live challenge.
    assert.equal(fields["tokenHash"]!["unique"], true);
    // The compare-and-set targets this column, and `affectedRows` treats a
    // returned row as one row on the strength of it being unique.
    assert.equal(fields["challengeId"]!["unique"], true);
    // Nullable: null is what "still live" means, and the consume guard
    // compares against it.
    assert.equal(fields["consumedAt"]!["required"], false);
    assert.equal(fields["attemptsRemaining"]!["type"], "number");

    const renamed = otplinkSchema({ model: "auth_otplink" });
    assert.ok(renamed["auth_otplink"], "the model name is configurable");
});

test("the plugin exposes the scanner-safe GET and the redeeming POST separately", () => {
    const plugin = otplink({ secret: SECRET, baseUrl: BASE_URL, mailer: async () => {} });

    assert.equal(plugin.id, "otplink");

    const page = plugin.endpoints.otplinkVerifyPage;
    const redeem = plugin.endpoints.otplinkVerify;

    assert.equal(page.options.method, "GET");
    assert.equal(redeem.options.method, "POST");
    assert.equal(page.path, "/otplink/verify");
    assert.equal(redeem.path, "/otplink/verify");

    // The GET must not accept a body at all: the whole point is that it is
    // safe in the RFC 9110 sense and redeems nothing. better-call's types
    // make `body` unavailable on a GET endpoint, so this also holds at
    // compile time.
    assert.ok(!("body" in page.options));
});

test("plugin configuration is validated at construction, not on the first request", () => {
    // Failing at startup rather than at 3am on a sign-in path is a property
    // the core deliberately has, and binding the store lazily could have
    // quietly lost it.
    assert.throws(
        () => otplink({ secret: "too-short", baseUrl: BASE_URL, mailer: async () => {} }),
        /secret/i,
    );
    assert.throws(
        () => otplink({ secret: SECRET, baseUrl: "http://example.com", mailer: async () => {} }),
        /https/i,
    );
});

test("request validators reject junk without pulling in a validation library", async () => {
    const schema = object({
        email: string({ description: "address", maxLength: 320 }),
        callbackURL: optional(string({ description: "target", maxLength: 2048 })),
        metadata: optional(record("extras")),
    });

    const validate = schema["~standard"].validate;
    assert.equal(schema["~standard"].version, 1);

    const ok = await validate({ email: "  person@example.com  ", metadata: { plan: "pro" } });
    if (ok.issues) throw new Error(`expected a valid body, got ${JSON.stringify(ok.issues)}`);
    assert.deepEqual(ok.value, { email: "person@example.com", metadata: { plan: "pro" } });

    // An absent optional field is omitted rather than set to undefined, which
    // is what `exactOptionalPropertyTypes` downstream expects.
    assert.ok(!("callbackURL" in ok.value));

    const missing = await validate({});
    assert.equal(missing.issues?.length, 1);
    assert.deepEqual(missing.issues?.[0]?.path, ["email"]);

    const blank = await validate({ email: "   " });
    assert.equal(blank.issues?.length, 1, "whitespace is not an address");

    // Unbounded strings reach an HMAC, so the ceiling is a real defence.
    const huge = await validate({ email: "a".repeat(400) });
    assert.equal(huge.issues?.length, 1);

    assert.equal((await validate("nope")).issues?.length, 1);
    assert.equal((await validate([])).issues?.length, 1);
});
