/**
 * Store conformance suite.
 *
 * A custom {@link TokenStore} can satisfy the TypeScript interface and still
 * be unsafe. The compiler cannot check that `consume` is atomic, that the
 * guard carries every liveness predicate, or that an exhausted challenge
 * stays dead. Those are the properties the whole design rests on, so they are
 * checked here instead.
 *
 * Deliberately runner-agnostic: it returns a report rather than calling
 * `expect`, so it works under node:test, Vitest, Jest, Deno, or a plain
 * script, and adds no dependency to a package that has none.
 *
 * ```ts
 * import { checkStoreConformance } from "linkotp/testing";
 *
 * const report = await checkStoreConformance({ createStore: () => myStore() });
 * assert.ok(report.passed, report.summary);
 * ```
 */

import type { Challenge, TokenStore } from "../types.ts";

export interface ConformanceHarness {
    /** Returns a fresh, empty store. Called once per check. */
    createStore(): TokenStore | Promise<TokenStore>;
    /** Optional cleanup after each check. */
    teardown?(store: TokenStore): void | Promise<void>;
}

export interface CheckResult {
    readonly name: string;
    readonly passed: boolean;
    /** Why it failed, or how it was satisfied. */
    readonly detail: string;
}

export interface ConformanceReport {
    readonly passed: boolean;
    readonly results: readonly CheckResult[];
    /** Human-readable digest, suitable as an assertion message. */
    readonly summary: string;
}

const BASE_TIME = 1_700_000_000_000;

function challenge(overrides: Partial<Challenge> = {}): Challenge {
    const id = overrides.id ?? `ch_${Math.random().toString(36).slice(2, 12)}`;
    return Object.freeze({
        id,
        email: "person@example.com",
        purpose: "sign-in",
        codeHash: `code_${id}`,
        tokenHash: `token_${id}`,
        bindingHash: null,
        metadata: null,
        attempts: 0,
        maxAttempts: 3,
        createdAt: BASE_TIME,
        expiresAt: BASE_TIME + 900_000,
        consumedAt: null,
        ...overrides,
    });
}

type Check = (store: TokenStore) => Promise<string | null>;

/** Each returns null on success, or a description of the violation. */
const CHECKS: ReadonlyArray<{ name: string; run: Check }> = [
    {
        name: "consume by token returns the challenge",
        run: async (store) => {
            const c = challenge();
            await store.insert(c);
            const got = await store.consume({
                by: "token",
                tokenHash: c.tokenHash,
                now: BASE_TIME + 1,
            });
            if (!got) return "consume returned null for a live challenge";
            if (got.id !== c.id) return `returned the wrong row: ${got.id} !== ${c.id}`;
            if (got.consumedAt === null) return "returned a row with consumedAt still null";
            return null;
        },
    },
    {
        name: "consume by code matches on email, purpose, and codeHash",
        run: async (store) => {
            const c = challenge();
            await store.insert(c);
            const got = await store.consume({
                by: "code",
                email: c.email,
                purpose: c.purpose,
                codeHash: c.codeHash,
                now: BASE_TIME + 1,
            });
            return got?.id === c.id ? null : "did not return the matching challenge";
        },
    },
    {
        name: "a challenge can be consumed only once",
        run: async (store) => {
            const c = challenge();
            await store.insert(c);
            const first = await store.consume({
                by: "token",
                tokenHash: c.tokenHash,
                now: BASE_TIME + 1,
            });
            const second = await store.consume({
                by: "token",
                tokenHash: c.tokenHash,
                now: BASE_TIME + 2,
            });
            if (!first) return "the first consume failed";
            if (second) return "SECOND CONSUME SUCCEEDED — single-use is not enforced";
            return null;
        },
    },
    {
        name: "concurrent consumes elect exactly one winner",
        run: async (store) => {
            const c = challenge();
            await store.insert(c);

            // Fired without awaiting in between, so they interleave at every
            // suspension point inside the implementation. A read-then-write
            // store fails here.
            const results = await Promise.all(
                Array.from({ length: 24 }, () =>
                    store.consume({ by: "token", tokenHash: c.tokenHash, now: BASE_TIME + 1 }),
                ),
            );
            const winners = results.filter((r) => r !== null).length;
            if (winners === 0) return "no caller won the race";
            if (winners > 1) {
                return `${winners} of 24 concurrent consumes succeeded — consume is NOT atomic. ` +
                    "Express it as a single guarded UPDATE, not a read followed by a write.";
            }
            return null;
        },
    },
    {
        name: "an expired challenge is never returned",
        run: async (store) => {
            const c = challenge({ expiresAt: BASE_TIME + 100 });
            await store.insert(c);
            const got = await store.consume({
                by: "token",
                tokenHash: c.tokenHash,
                now: BASE_TIME + 101,
            });
            return got ? "returned a challenge past its expiry" : null;
        },
    },
    {
        name: "expiry is exclusive at the boundary",
        run: async (store) => {
            const c = challenge({ expiresAt: BASE_TIME + 100 });
            await store.insert(c);
            const got = await store.consume({
                by: "token",
                tokenHash: c.tokenHash,
                now: BASE_TIME + 99,
            });
            return got ? null : "rejected a challenge that had not yet expired";
        },
    },
    {
        name: "an attempt-exhausted challenge is never returned",
        run: async (store) => {
            const c = challenge({ attempts: 3, maxAttempts: 3 });
            await store.insert(c);
            const got = await store.consume({
                by: "token",
                tokenHash: c.tokenHash,
                now: BASE_TIME + 1,
            });
            return got ? "returned a challenge whose attempts reached maxAttempts" : null;
        },
    },
    {
        name: "registerFailedAttempt increments and reports remaining",
        run: async (store) => {
            const c = challenge({ maxAttempts: 3 });
            await store.insert(c);
            const first = await store.registerFailedAttempt({
                email: c.email,
                purpose: c.purpose,
                now: BASE_TIME + 1,
            });
            if (!first.found) return "reported no live challenge when one exists";
            if (first.remaining !== 2) return `expected 2 remaining, got ${first.remaining}`;

            const second = await store.registerFailedAttempt({
                email: c.email,
                purpose: c.purpose,
                now: BASE_TIME + 2,
            });
            if (second.remaining !== 1) return `expected 1 remaining, got ${second.remaining}`;
            return null;
        },
    },
    {
        name: "exhausting attempts retires the challenge",
        run: async (store) => {
            const c = challenge({ maxAttempts: 2 });
            await store.insert(c);
            for (let i = 0; i < 2; i++) {
                await store.registerFailedAttempt({
                    email: c.email,
                    purpose: c.purpose,
                    now: BASE_TIME + 1 + i,
                });
            }
            const got = await store.consume({
                by: "token",
                tokenHash: c.tokenHash,
                now: BASE_TIME + 5,
            });
            return got ? "a challenge survived exhausting its attempt budget" : null;
        },
    },
    {
        name: "registerFailedAttempt reports not-found when nothing is live",
        run: async (store) => {
            const outcome = await store.registerFailedAttempt({
                email: "nobody@example.com",
                purpose: "sign-in",
                now: BASE_TIME,
            });
            return outcome.found === false
                ? null
                : "claimed to find a live challenge for an unknown address";
        },
    },
    {
        name: "registerFailedAttempt separates exhaustion from absence",
        run: async (store) => {
            // Once the budget is spent the challenge still exists. Reporting
            // it as absent would turn "no attempts left" into "wrong code" on
            // every subsequent submission, looping the user forever.
            const c = challenge({ maxAttempts: 1 });
            await store.insert(c);
            await store.registerFailedAttempt({
                email: c.email,
                purpose: c.purpose,
                now: BASE_TIME + 1,
            });
            const after = await store.registerFailedAttempt({
                email: c.email,
                purpose: c.purpose,
                now: BASE_TIME + 2,
            });
            if (!after.found) return "an exhausted challenge was reported as absent";
            if (after.remaining !== 0) return `expected 0 remaining, got ${after.remaining}`;
            return null;
        },
    },
    {
        name: "delete removes a challenge",
        run: async (store) => {
            const c = challenge();
            await store.insert(c);
            await store.delete(c.id);
            const got = await store.consume({
                by: "token",
                tokenHash: c.tokenHash,
                now: BASE_TIME + 1,
            });
            return got ? "a deleted challenge was still consumable" : null;
        },
    },
    {
        name: "countIssuedSince counts within the window only",
        run: async (store) => {
            await store.insert(challenge({ createdAt: BASE_TIME }));
            await store.insert(challenge({ createdAt: BASE_TIME + 5_000 }));
            await store.insert(challenge({ createdAt: BASE_TIME - 100_000 }));

            const count = await store.countIssuedSince({
                email: "person@example.com",
                purpose: "sign-in",
                since: BASE_TIME - 1,
            });
            return count === 2 ? null : `expected 2 within the window, got ${count}`;
        },
    },
    {
        name: "countIssuedSince counts consumed challenges too",
        run: async (store) => {
            const c = challenge();
            await store.insert(c);
            await store.consume({ by: "token", tokenHash: c.tokenHash, now: BASE_TIME + 1 });
            const count = await store.countIssuedSince({
                email: c.email,
                purpose: c.purpose,
                since: BASE_TIME - 1,
            });
            // Otherwise redeeming a code resets the send quota, and the
            // per-address cap stops being a cap.
            return count === 1 ? null : `expected consumed rows to count, got ${count}`;
        },
    },
    {
        name: "deleteExpired removes only expired rows",
        run: async (store) => {
            await store.insert(challenge({ expiresAt: BASE_TIME + 100 }));
            const live = challenge({ expiresAt: BASE_TIME + 900_000 });
            await store.insert(live);

            const removed = await store.deleteExpired(BASE_TIME + 200);
            if (removed !== 1) return `expected to remove 1 row, removed ${removed}`;

            const got = await store.consume({
                by: "token",
                tokenHash: live.tokenHash,
                now: BASE_TIME + 300,
            });
            return got ? null : "the sweep removed a live challenge";
        },
    },
    {
        name: "metadata survives a round trip",
        run: async (store) => {
            const metadata = { plan: "pro", invited: true, seats: 3, tag: null };
            const c = challenge({ metadata });
            await store.insert(c);
            const got = await store.consume({
                by: "token",
                tokenHash: c.tokenHash,
                now: BASE_TIME + 1,
            });
            if (!got) return "consume returned null";
            if (JSON.stringify(got.metadata) !== JSON.stringify(metadata)) {
                return `metadata changed: ${JSON.stringify(got.metadata)}`;
            }
            return null;
        },
    },
    {
        name: "consume distinguishes challenges on the same address",
        run: async (store) => {
            const first = challenge();
            const second = challenge();
            await store.insert(first);
            await store.insert(second);

            const got = await store.consume({
                by: "code",
                email: second.email,
                purpose: second.purpose,
                codeHash: second.codeHash,
                now: BASE_TIME + 1,
            });
            if (got?.id !== second.id) return "matched the wrong challenge for a shared address";

            const other = await store.consume({
                by: "token",
                tokenHash: first.tokenHash,
                now: BASE_TIME + 2,
            });
            return other?.id === first.id ? null : "consuming one challenge invalidated another";
        },
    },
];

export async function checkStoreConformance(
    harness: ConformanceHarness,
): Promise<ConformanceReport> {
    const results: CheckResult[] = [];

    for (const { name, run } of CHECKS) {
        const store = await harness.createStore();
        try {
            const violation = await run(store);
            results.push({
                name,
                passed: violation === null,
                detail: violation ?? "ok",
            });
        } catch (error) {
            results.push({
                name,
                passed: false,
                detail: `threw: ${error instanceof Error ? error.message : String(error)}`,
            });
        } finally {
            await harness.teardown?.(store);
        }
    }

    const failures = results.filter((r) => !r.passed);
    const summary =
        failures.length === 0
            ? `All ${results.length} store conformance checks passed.`
            : [
                  `${failures.length} of ${results.length} store conformance checks failed:`,
                  ...failures.map((f) => `  - ${f.name}: ${f.detail}`),
              ].join("\n");

    return { passed: failures.length === 0, results, summary };
}
