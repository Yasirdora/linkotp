import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";

import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { memoryAdapter } from "better-auth/adapters/memory";
import type { BetterAuthPlugin } from "better-auth/types";

import { checkStoreConformance } from "../src/testing/conformance.ts";
import {
    affectedRows,
    createBetterAuthStore,
    DEFAULT_MODEL,
    type BetterAuthAdapterLike,
} from "../src/better-auth/store.ts";
import { otplinkSchema } from "../src/better-auth/schema.ts";
import { otplink } from "../src/better-auth/plugin.ts";
import { otplinkClient } from "../src/better-auth/client.ts";
import { OTPLINK_ERROR_CODES } from "../src/better-auth/error-codes.ts";
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

test("the Better Auth store satisfies the conformance suite (memory adapter)", async () => {
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

    // `binding` is part of the options this plugin inherits but not yet part
    // of what it implements. Silently ignoring it would leave a deployment
    // believing it had bound challenges to the originating browser when every
    // challenge was in fact unbound.
    assert.throws(
        () =>
            otplink({
                secret: SECRET,
                baseUrl: BASE_URL,
                mailer: async () => {},
                binding: { enabled: true },
            }),
        /binding/i,
    );
    assert.doesNotThrow(() =>
        otplink({
            secret: SECRET,
            baseUrl: BASE_URL,
            mailer: async () => {},
            binding: { enabled: false },
        }),
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

    // Optionality has to survive into the *inferred* type, not just the
    // runtime check. When it did not, every caller was told to supply every
    // optional field, and no runtime assertion in this file noticed.
    type Body = NonNullable<(typeof schema)["~standard"]["types"]>["input"];
    const minimal: Body = { email: "person@example.com" };
    const full: Body = {
        email: "person@example.com",
        callbackURL: "/dashboard",
        metadata: { plan: "pro" },
    };
    assert.equal(minimal.email, full.email);
});


/**
 * A complete Better Auth instance with the plugin mounted.
 *
 * Everything above this point tests otplink's own pieces. This tests the
 * thing a user actually installs: real routing, real body parsing, real
 * middleware, real session cookies. It is the only level at which a mistake
 * in the *contract* — a rejected content type, a plugin shape Better Auth
 * will not accept — can show up at all.
 */
function instance() {
    const db: Record<string, unknown[]> = {
        user: [],
        session: [],
        account: [],
        verification: [],
        [DEFAULT_MODEL]: [],
    };
    const sent: { text: string; html: string }[] = [];

    const auth = betterAuth({
        secret: "a-better-auth-secret-that-is-at-least-32-chars",
        baseURL: "https://example.com",
        database: memoryAdapter(db),
        plugins: [
            otplink({
                secret: SECRET,
                baseUrl: BASE_URL,
                minimumStartDurationMs: 0,
                mailer: async (message) => {
                    sent.push({ text: message.text, html: message.html });
                },
            }),
        ],
    });

    const last = () => {
        const message = sent.at(-1);
        if (!message) throw new Error("no message was sent");
        const link = /https?:\/\/[^\s]+/.exec(message.text)?.[0];
        const code = /\n {4}([A-Z0-9 ]+)\n/.exec(message.text)?.[1]?.replace(/ /g, "");
        if (!link || !code) throw new Error("could not recover the link or code");
        return { link, code, token: new URL(link).searchParams.get("token")! };
    };

    const post = (path: string, body: Record<string, string>) =>
        auth.handler(
            new Request(`https://example.com/api/auth${path}`, {
                method: "POST",
                headers: {
                    "content-type": "application/x-www-form-urlencoded",
                    origin: "https://example.com",
                },
                body: new URLSearchParams(body),
            }),
        );

    /** `noUncheckedIndexedAccess` is on, and these tables always exist. */
    const rows = (table: string): unknown[] => db[table] ?? [];

    return { auth, db, sent, last, post, rows };
}

test("the plugin satisfies Better Auth's plugin contract", () => {
    // A type-level assertion, checked by `npm run typecheck`. It earns its
    // place: `$ERROR_CODES` must be `Record<string, RawError>` rather than
    // the plain message map it looks like it should be, and nothing else in
    // this file would have caught that — every behavioural test passed while
    // the plugin was not a valid BetterAuthPlugin at all.
    const plugin: BetterAuthPlugin = otplink({
        secret: SECRET,
        baseUrl: BASE_URL,
        mailer: async () => {},
    });
    assert.equal(plugin.id, "otplink");
    assert.equal(OTPLINK_ERROR_CODES.OTPLINK_INVALID_TOKEN.code, "OTPLINK_INVALID_TOKEN");
    assert.equal(typeof OTPLINK_ERROR_CODES.OTPLINK_INVALID_TOKEN.message, "string");

    // The client half is inferred from the server half, so this is the only
    // place the two are checked against each other.
    const client = otplinkClient();
    assert.equal(client.id, "otplink");
    assert.equal(client.atomListeners[0].matcher("/otplink/verify"), true);
    assert.equal(client.atomListeners[0].matcher("/sign-in/otplink"), false);
});

test("a scanner cannot spend the link, but the person can", async () => {
    const { auth, last, post, rows } = instance();

    await auth.api.signInOtplink({
        body: { email: "person@example.com" },
        headers: new Headers(),
    });

    const { link, token } = last();
    // The link has to resolve to where Better Auth is actually mounted.
    assert.equal(new URL(link).pathname, "/api/auth/otplink/verify");

    // Exactly what Defender Safe Links, Proofpoint, Mimecast and Barracuda
    // do to every URL in inbound mail, before the recipient sees it.
    for (let i = 0; i < 3; i++) {
        const scan = await auth.handler(new Request(link, { method: "GET" }));
        assert.equal(scan.status, 200, "the confirmation page renders");
        assert.equal(scan.headers.get("set-cookie"), null, "a GET must not mint a session");
        assert.match(scan.headers.get("content-security-policy") ?? "", /default-src 'none'/);
        assert.match(scan.headers.get("cache-control") ?? "", /no-store/);
        assert.equal(scan.headers.get("referrer-policy"), "no-referrer");
    }
    assert.equal(rows("session").length, 0, "three scans created no sessions");

    // The confirmation page submits a plain HTML form, so this arrives as
    // form-urlencoded. Better Auth's router rejects that with 415 unless the
    // endpoint opts in, which is invisible to every test below this level.
    const redeem = await post("/otplink/verify", { token });
    assert.equal(redeem.status, 302, "the link flow redirects rather than returning JSON");
    assert.match(redeem.headers.get("set-cookie") ?? "", /session_token=/);
    assert.equal(redeem.headers.get("location"), "https://example.com/");
    assert.equal(rows("user").length, 1, "the account was provisioned");
    assert.equal(rows("session").length, 1);

    // The scanner's three fetches did not consume it; this second redemption
    // must, because the first one did.
    const replay = await post("/otplink/verify", { token });
    assert.equal(replay.status, 302);
    assert.equal(
        replay.headers.get("location"),
        "https://example.com/?error=invalid_token",
        "an expired or spent link lands on a page, not on a JSON error body",
    );
    assert.equal(rows("session").length, 1, "the replay created no second session");
});

test("the typed code is a second, independent way in", async () => {
    const { auth, last, rows } = instance();

    await auth.api.signInOtplink({
        body: { email: "person@example.com" },
        headers: new Headers(),
    });
    const { code, token } = last();

    const wrong = await auth.handler(
        new Request("https://example.com/api/auth/sign-in/otplink/code", {
            method: "POST",
            headers: { "content-type": "application/json", origin: "https://example.com" },
            body: JSON.stringify({ email: "person@example.com", code: "AAAAAA" }),
        }),
    );
    assert.equal(wrong.status, 400);
    assert.equal(rows("session").length, 0);

    const right = await auth.handler(
        new Request("https://example.com/api/auth/sign-in/otplink/code", {
            method: "POST",
            headers: { "content-type": "application/json", origin: "https://example.com" },
            body: JSON.stringify({ email: "person@example.com", code }),
        }),
    );
    assert.equal(right.status, 200);
    assert.match(right.headers.get("set-cookie") ?? "", /session_token=/);
    assert.equal(rows("session").length, 1);

    // Redeeming either arm retires the other: they are two secrets on one
    // challenge, not two challenges.
    const link = await auth.handler(
        new Request("https://example.com/api/auth/otplink/verify", {
            method: "POST",
            headers: {
                "content-type": "application/x-www-form-urlencoded",
                origin: "https://example.com",
            },
            body: new URLSearchParams({ token }),
        }),
    );
    assert.equal(link.headers.get("location"), "https://example.com/?error=invalid_token");
    assert.equal(rows("session").length, 1);
});


test("the emailed link resolves wherever Better Auth is mounted", async () => {
    // The link is built at send time from `baseURL` and `basePath`, and a
    // wrong path here is invisible until a real user clicks a real email.
    // `baseURL` sometimes already carries the base path and sometimes does
    // not, which is the case the derivation has to get right.
    const mount = async (config: { baseURL: string; basePath?: string }) => {
        const db: Record<string, unknown[]> = {
            user: [],
            session: [],
            account: [],
            verification: [],
            [DEFAULT_MODEL]: [],
        };
        const sent: string[] = [];
        const auth = betterAuth({
            secret: "a-better-auth-secret-that-is-at-least-32-chars",
            baseURL: config.baseURL,
            ...(config.basePath !== undefined ? { basePath: config.basePath } : {}),
            database: memoryAdapter(db),
            plugins: [
                otplink({
                    secret: SECRET,
                    baseUrl: BASE_URL,
                    minimumStartDurationMs: 0,
                    mailer: async (message) => {
                        sent.push(message.text);
                    },
                }),
            ],
        });

        await auth.api.signInOtplink({
            body: { email: "person@example.com" },
            headers: new Headers(),
        });

        const link = /https?:\/\/[^\s]+/.exec(sent[0] ?? "")?.[0];
        assert.ok(link, "the email carried no link");
        const page = await auth.handler(new Request(link, { method: "GET" }));
        assert.equal(page.status, 200, "the emailed link must reach the confirmation page");

        // The page has to post back to itself, or the link arm dead-ends.
        const action = /action="([^"]+)"/.exec(await page.text())?.[1];
        return { path: new URL(link).pathname, action };
    };

    assert.deepEqual(await mount({ baseURL: "https://example.com" }), {
        path: "/api/auth/otplink/verify",
        action: "https://example.com/api/auth/otplink/verify",
    });

    assert.deepEqual(await mount({ baseURL: "https://example.com", basePath: "/auth" }), {
        path: "/auth/otplink/verify",
        action: "https://example.com/auth/otplink/verify",
    });

    // baseURL already carrying the path must not double it.
    assert.deepEqual(await mount({ baseURL: "https://example.com/api/auth" }), {
        path: "/api/auth/otplink/verify",
        action: "https://example.com/api/auth/otplink/verify",
    });
});


/**
 * A Better Auth instance on real SQL, with the plugin's table created by
 * Better Auth's own migrator.
 *
 * `node:sqlite` is a Node builtin and Better Auth accepts a `DatabaseSync`
 * directly, so this costs no dependency — the same trick the SQL store's own
 * suite uses.
 *
 * The memory adapter proves the store's logic. It cannot prove the claims
 * that logic *rests* on, because it is a JavaScript object rather than a
 * database: that `{ operator: "eq", value: null }` compiles to `IS NULL`
 * rather than `= NULL`, that a `date` column compares correctly against a
 * `Date`, and above all that the guarded `updateMany` becomes a single
 * `UPDATE ... WHERE ...` whose affected-row count elects exactly one winner.
 * Those were read out of adapter source and reasoned about; here they are
 * executed.
 */
async function sqlInstance() {
    const database = new DatabaseSync(":memory:");
    const auth = betterAuth({
        secret: "a-better-auth-secret-that-is-at-least-32-chars",
        baseURL: "https://example.com",
        database,
        plugins: [
            otplink({
                secret: SECRET,
                baseUrl: BASE_URL,
                minimumStartDurationMs: 0,
                mailer: async () => {},
            }),
        ],
    });

    // Not hand-written DDL: the table comes from `otplinkSchema` through the
    // same migrator `@better-auth/cli migrate` runs, so a schema this package
    // declares but Better Auth cannot migrate fails right here.
    const { runMigrations, toBeCreated } = await getMigrations(auth.options);
    await runMigrations();

    const { adapter } = await auth.$context;
    return { auth, database, adapter, planned: toBeCreated.map((t) => t.table) };
}

test("the plugin's declared schema migrates to a real database", async () => {
    const { database, planned } = await sqlInstance();
    try {
        assert.ok(planned.includes(DEFAULT_MODEL), "the migrator planned the challenge table");

        const columns = new Map(
            (
                database.prepare(`PRAGMA table_info(${DEFAULT_MODEL})`).all() as {
                    name: string;
                    notnull: number;
                }[]
            ).map((c) => [c.name, c]),
        );

        for (const required of [
            "challengeId",
            "email",
            "purpose",
            "codeHash",
            "tokenHash",
            "attemptsRemaining",
            "maxAttempts",
            "createdAt",
            "expiresAt",
        ]) {
            assert.equal(columns.get(required)?.notnull, 1, `${required} must be NOT NULL`);
        }

        // Null is what "still live" means, and the consume guard compares
        // against it. A NOT NULL consumedAt would make every challenge dead.
        assert.equal(columns.get("consumedAt")?.notnull, 0, "consumedAt must be nullable");
        assert.equal(columns.get("bindingHash")?.notnull, 0);

        // A token collision must fail loudly at insert rather than silently
        // overwrite a live challenge, and `affectedRows` treats a returned row
        // as one row on the strength of challengeId being unique.
        const uniques = (
            database.prepare(`PRAGMA index_list(${DEFAULT_MODEL})`).all() as {
                name: string;
                unique: number;
            }[]
        )
            .filter((i) => i.unique === 1)
            .flatMap(
                (i) =>
                    (
                        database.prepare(`PRAGMA index_info(${i.name})`).all() as {
                            name: string;
                        }[]
                    ).map((c) => c.name),
            );

        assert.ok(uniques.includes("tokenHash"), "tokenHash must be UNIQUE in the database");
        assert.ok(uniques.includes("challengeId"), "challengeId must be UNIQUE in the database");
    } finally {
        database.close();
    }
});

test("the Better Auth store satisfies the conformance suite (real SQL)", async () => {
    const { database, adapter } = await sqlInstance();
    try {
        const report = await checkStoreConformance({
            createStore: () => {
                // A fresh, empty store per check, without re-migrating.
                database.prepare(`DELETE FROM ${DEFAULT_MODEL}`).run();
                return createBetterAuthStore({ adapter: adapter as unknown as BetterAuthAdapterLike });
            },
        });

        assert.ok(report.passed, report.summary);

        // The concurrency check is the one that matters most: on real SQL it
        // is the database's row lock electing the winner, not JavaScript's
        // single thread, which is the only place that claim can be tested.
        const race = report.results.find((r) => r.name.includes("concurrent"));
        assert.equal(race?.passed, true, race?.detail);
    } finally {
        database.close();
    }
});

test("a full sign-in round trip works on real SQL", async () => {
    const database = new DatabaseSync(":memory:");
    const sent: string[] = [];
    const auth = betterAuth({
        secret: "a-better-auth-secret-that-is-at-least-32-chars",
        baseURL: "https://example.com",
        database,
        plugins: [
            otplink({
                secret: SECRET,
                baseUrl: BASE_URL,
                minimumStartDurationMs: 0,
                mailer: async (message) => {
                    sent.push(message.text);
                },
            }),
        ],
    });

    try {
        await (await getMigrations(auth.options)).runMigrations();

        await auth.api.signInOtplink({
            body: { email: "person@example.com" },
            headers: new Headers(),
        });

        const link = /https?:\/\/[^\s]+/.exec(sent[0] ?? "")?.[0];
        assert.ok(link);
        const token = new URL(link).searchParams.get("token")!;

        const scan = await auth.handler(new Request(link, { method: "GET" }));
        assert.equal(scan.status, 200);
        assert.equal(scan.headers.get("set-cookie"), null);

        const redeem = () =>
            auth.handler(
                new Request("https://example.com/api/auth/otplink/verify", {
                    method: "POST",
                    headers: {
                        "content-type": "application/x-www-form-urlencoded",
                        origin: "https://example.com",
                    },
                    body: new URLSearchParams({ token }),
                }),
            );

        const first = await redeem();
        assert.equal(first.status, 302);
        assert.match(first.headers.get("set-cookie") ?? "", /session_token=/);

        const sessions = database.prepare("SELECT COUNT(*) AS n FROM session").get() as {
            n: number;
        };
        assert.equal(sessions.n, 1);

        // Single-use, enforced by the database this time.
        const replay = await redeem();
        assert.equal(replay.headers.get("location"), "https://example.com/?error=invalid_token");
        const after = database.prepare("SELECT COUNT(*) AS n FROM session").get() as { n: number };
        assert.equal(after.n, 1, "the replay created no second session");
    } finally {
        database.close();
    }
});
