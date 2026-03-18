/**
 * A {@link TokenStore} backed by Better Auth's database adapter.
 *
 * Better Auth already owns a database connection, a schema, and a migration
 * story for whichever driver the application chose — Drizzle, Prisma, Kysely,
 * D1, Mongo. Asking users to configure a second connection for otplink would
 * be both redundant and a source of drift, so this store speaks the adapter
 * interface instead and inherits all of it.
 *
 * ## Why this is not just `createSqlStore` with a different driver
 *
 * The SQL store expresses its compare-and-set as one guarded statement:
 *
 * ```sql
 * UPDATE ... SET consumed_at = :now WHERE token_hash = :t AND attempts < max_attempts ...
 * ```
 *
 * Better Auth's `Where[]` cannot express `attempts < max_attempts`. Every
 * clause compares a *field to a literal value*, never a field to another
 * field, so the attempt budget has to be re-modelled as something a literal
 * can be compared against. This store therefore persists
 * `attemptsRemaining` and guards `attemptsRemaining > 0`, counting down to
 * zero instead of up to a ceiling. That is semantically identical — the
 * `Challenge` surface still reports `attempts` and `maxAttempts` — and it is
 * expressible as `{ field, operator: "gt", value: 0 }` on every adapter.
 *
 * @see {@link TokenStore.consume} for the atomicity contract this must meet.
 */

import type {
    Challenge,
    ConsumeQuery,
    FailedAttemptOutcome,
    Purpose,
    TokenStore,
} from "../types.ts";

/**
 * The subset of Better Auth's `Where` clause this store relies on.
 *
 * Declared structurally rather than imported so the store compiles, and can
 * be tested, without Better Auth installed — the package is an *optional*
 * peer dependency, and a type-only import would make it mandatory for anyone
 * running `tsc` over their `node_modules`. A real `Where` satisfies this.
 */
export interface AdapterWhere {
    readonly field: string;
    readonly value: string | number | boolean | Date | null;
    readonly operator?: "eq" | "ne" | "lt" | "lte" | "gt" | "gte";
    readonly connector?: "AND" | "OR";
}

/**
 * The six adapter methods otplink needs.
 *
 * Better Auth's `DBAdapter` is much wider than this; narrowing it here
 * documents the actual coupling and keeps the store usable with any object
 * that happens to satisfy these signatures, including the test double.
 */
export interface BetterAuthAdapterLike {
    create<T extends Record<string, unknown>, R = T>(data: {
        model: string;
        data: Omit<T, "id">;
    }): Promise<R>;
    findOne<T>(data: { model: string; where: AdapterWhere[] }): Promise<T | null>;
    findMany<T>(data: { model: string; where?: AdapterWhere[] }): Promise<T[]>;
    count(data: { model: string; where?: AdapterWhere[] }): Promise<number>;
    /**
     * Applies a guarded update and reports what it changed. That report is
     * the compare-and-set result this store is built on: it compiles to a
     * single `UPDATE ... WHERE ...` on every first-party adapter, so a guard
     * matching exactly one row elects exactly one winner.
     *
     * Typed `unknown` rather than `number` on purpose. Better Auth documents
     * this as `Promise<number>`, and Kysely, Prisma, and Mongo honour that —
     * but the Drizzle adapter returns the raw driver result object and the
     * memory adapter returns the updated record. Declaring the truth here and
     * normalizing in {@link affectedRows} is what keeps the store correct on
     * all five rather than only on the three that match their own docs.
     */
    updateMany(data: {
        model: string;
        where: AdapterWhere[];
        update: Record<string, unknown>;
    }): Promise<unknown>;
    delete(data: { model: string; where: AdapterWhere[] }): Promise<void>;
    deleteMany(data: { model: string; where: AdapterWhere[] }): Promise<number>;
}

export interface BetterAuthStoreOptions {
    readonly adapter: BetterAuthAdapterLike;
    /**
     * Model name to read and write. Must match the key in the plugin schema.
     *
     * @default "otplinkChallenge"
     */
    readonly model?: string;
}

/** Default model name, shared with the plugin's schema declaration. */
export const DEFAULT_MODEL = "otplinkChallenge";

/**
 * Slack added to the provable retry bound, to absorb reads that lose for a
 * reason other than a competing decrement.
 */
const CAS_ROUND_SLACK = 2;

/** The row as Better Auth stores and returns it. */
interface Row extends Record<string, unknown> {
    challengeId: string;
    email: string;
    purpose: string;
    codeHash: string;
    tokenHash: string;
    bindingHash: string | null;
    metadata: string | null;
    attemptsRemaining: number;
    maxAttempts: number;
    createdAt: Date | string | number;
    expiresAt: Date | string | number;
    consumedAt: Date | string | number | null;
}

/**
 * Coerces a stored timestamp back to epoch milliseconds.
 *
 * Adapters are not consistent about what a `date` field round-trips as: a
 * `Date` from Drizzle and Kysely, an ISO string from some driver
 * configurations, a number from others. otplink's surface is epoch
 * milliseconds throughout, so every read normalizes here rather than leaving
 * each call site to guess.
 */
function toEpoch(value: Date | string | number): number {
    if (value instanceof Date) return value.getTime();
    if (typeof value === "number") return value;
    return new Date(value).getTime();
}

/** Driver result keys that carry an affected-row count, in preference order. */
const COUNT_KEYS = [
    "rowCount", // node-postgres
    "affectedRows", // mysql2
    "rowsAffected", // libSQL, D1
    "changes", // better-sqlite3, node:sqlite
    "numUpdatedRows", // Kysely
    "modifiedCount", // MongoDB
    "count", // Prisma
] as const;

/**
 * Normalizes whatever `updateMany` returned into an affected-row count.
 *
 * Better Auth's adapter interface promises a number. Two of its five
 * first-party adapters do not deliver one: Drizzle returns the underlying
 * driver's result object, and the memory adapter returns the updated record.
 * Since the entire single-use guarantee rests on distinguishing "this caller
 * claimed the row" from "someone else did", guessing here would be
 * unacceptable, and trusting the declared type would break sign-in on Drizzle
 * outright.
 *
 * The record-shaped case resolves to 1 only because **every guarded update in
 * this store targets a unique key** — `challengeId`, which the schema marks
 * unique. At most one row can match, so a returned row means that row. If
 * that invariant is ever broken, this function becomes wrong; do not add a
 * guarded update here keyed on anything non-unique.
 *
 * Anything unrecognized returns 0, which fails closed: the caller concludes
 * it did not win and declines the sign-in. A denied sign-in is a loud,
 * immediately visible bug; a wrongly granted one is a silent security
 * failure.
 */
export function affectedRows(result: unknown): number {
    if (typeof result === "number") return Number.isFinite(result) ? result : 0;
    if (typeof result === "bigint") return Number(result);
    if (result === null || result === undefined) return 0;
    if (Array.isArray(result)) return result.length;

    if (typeof result === "object") {
        const record = result as Record<string, unknown>;

        for (const key of COUNT_KEYS) {
            const value = record[key];
            if (typeof value === "number" && Number.isFinite(value)) return value;
            if (typeof value === "bigint") return Number(value);
        }

        // An adapter that hands back the row it updated. Recognized by the
        // column only otplink writes, so an unrelated result object cannot be
        // mistaken for a successful claim.
        if (typeof record["challengeId"] === "string") return 1;
    }

    return 0;
}

function toChallenge(row: Row): Challenge {
    const maxAttempts = Number(row.maxAttempts);
    const remaining = Math.max(0, Number(row.attemptsRemaining));

    return Object.freeze({
        id: row.challengeId,
        email: row.email,
        purpose: row.purpose as Purpose,
        codeHash: row.codeHash,
        tokenHash: row.tokenHash,
        bindingHash: row.bindingHash ?? null,
        // Stored as a JSON string rather than a `json` column: json support
        // is the least uniform corner of the adapter surface, and a string
        // behaves identically everywhere.
        metadata:
            row.metadata === null || row.metadata === undefined
                ? null
                : (JSON.parse(row.metadata) as Record<string, unknown>),
        // Projected back onto the public shape. The column counts down; the
        // interface counts up.
        attempts: Math.max(0, maxAttempts - remaining),
        maxAttempts,
        createdAt: toEpoch(row.createdAt),
        expiresAt: toEpoch(row.expiresAt),
        consumedAt: row.consumedAt === null || row.consumedAt === undefined
            ? null
            : toEpoch(row.consumedAt),
    });
}

export function createBetterAuthStore(options: BetterAuthStoreOptions): TokenStore {
    const { adapter } = options;
    const model = options.model ?? DEFAULT_MODEL;

    /**
     * The liveness predicates, as adapter clauses.
     *
     * These are the same four conditions the SQL store puts in its `WHERE`,
     * and they belong inside every guarded update for the same reason:
     * evaluating them in calling code reintroduces the race the guard exists
     * to close.
     *
     * `{ operator: "eq", value: null }` compiles to `IS NULL` — verified in
     * the Kysely, Drizzle, and Prisma adapters — not to `= NULL`, which would
     * silently match nothing.
     */
    const live = (now: number): AdapterWhere[] => [
        { field: "consumedAt", operator: "eq", value: null },
        { field: "expiresAt", operator: "gt", value: new Date(now) },
        { field: "attemptsRemaining", operator: "gt", value: 0 },
    ];

    /** Liveness minus the attempt budget: "does a challenge exist at all". */
    const present = (now: number): AdapterWhere[] => [
        { field: "consumedAt", operator: "eq", value: null },
        { field: "expiresAt", operator: "gt", value: new Date(now) },
    ];

    /**
     * Spends one attempt against a single challenge, exactly once.
     *
     * Better Auth's `update` payload carries literal values, not expressions,
     * so `attemptsRemaining = attemptsRemaining - 1` cannot be pushed into
     * the database the way the SQL store pushes `attempts = attempts + 1`.
     * Read-then-write would then lose concurrent decrements, and a lost
     * decrement is a free brute-force guess.
     *
     * The fix is an optimistic compare-and-set: read the current value, then
     * update *guarded on that exact value*. Two racers read the same number;
     * only one update matches, and the loser re-reads rather than
     * overwriting. The counter can never go backwards or skip.
     *
     * @returns attempts left after this call, or null if no live challenge
     *          remains — which is not the same as zero.
     */
    async function spendAttempt(challengeId: string, now: number): Promise<number | null> {
        // Derived, not guessed. Every losing round means some other caller's
        // decrement landed, so the counter is strictly lower on the next read.
        // It starts at `maxAttempts` and is floored at zero, which bounds the
        // losing rounds by `maxAttempts` — past that the budget is genuinely
        // spent and the early return below fires. A fixed cap would instead
        // drop a decrement as soon as concurrency exceeded it, and a dropped
        // decrement is a free brute-force guess.
        let rounds = Number.POSITIVE_INFINITY;

        for (let round = 0; round < rounds; round++) {
            const row = await adapter.findOne<Row>({
                model,
                where: [{ field: "challengeId", value: challengeId }, ...present(now)],
            });
            if (!row) return null;

            if (round === 0) {
                rounds = Math.max(1, Number(row.maxAttempts)) + CAS_ROUND_SLACK;
            }

            const remaining = Math.max(0, Number(row.attemptsRemaining));
            // Already spent. Not an error, and not something to decrement
            // past zero: the challenge is retired but still present, and the
            // caller needs to be able to tell those apart.
            if (remaining === 0) return 0;

            const affected = affectedRows(
                await adapter.updateMany({
                    model,
                    where: [
                        { field: "challengeId", value: challengeId },
                        // The compare half of the compare-and-set.
                        { field: "attemptsRemaining", operator: "eq", value: remaining },
                        ...present(now),
                    ],
                    update: { attemptsRemaining: remaining - 1 },
                }),
            );
            if (affected === 1) return remaining - 1;
        }

        // Contention never cleared. Report what is visible without claiming a
        // decrement that did not happen; enforcement still lives in the
        // consume guard, so an over-reported budget cannot let a challenge
        // through.
        const row = await adapter.findOne<Row>({
            model,
            where: [{ field: "challengeId", value: challengeId }, ...present(now)],
        });
        return row ? Math.max(0, Number(row.attemptsRemaining)) : null;
    }

    return {
        async insert(challenge: Challenge): Promise<void> {
            // `challengeId` rather than the adapter's own `id`: Better Auth
            // generates primary keys itself, and several adapters require
            // that (Mongo's ObjectId, for one). Carrying otplink's id in its
            // own unique column keeps both identifiers valid and avoids
            // depending on `forceAllowId`.
            await adapter.create<Row>({
                model,
                data: {
                    challengeId: challenge.id,
                    email: challenge.email,
                    purpose: challenge.purpose,
                    codeHash: challenge.codeHash,
                    tokenHash: challenge.tokenHash,
                    bindingHash: challenge.bindingHash,
                    metadata:
                        challenge.metadata === null ? null : JSON.stringify(challenge.metadata),
                    attemptsRemaining: Math.max(0, challenge.maxAttempts - challenge.attempts),
                    maxAttempts: challenge.maxAttempts,
                    createdAt: new Date(challenge.createdAt),
                    expiresAt: new Date(challenge.expiresAt),
                    consumedAt:
                        challenge.consumedAt === null ? null : new Date(challenge.consumedAt),
                },
            });
        },

        async consume(query: ConsumeQuery): Promise<Challenge | null> {
            const now = query.now;

            const key: AdapterWhere[] =
                query.by === "token"
                    ? [{ field: "tokenHash", value: query.tokenHash }]
                    : [
                          { field: "email", value: query.email },
                          { field: "purpose", value: query.purpose },
                          { field: "codeHash", value: query.codeHash },
                      ];

            // Locating the row is not the claim. This read only resolves the
            // lookup key to a primary key; it carries the liveness predicates
            // so that an expired or retired row is never even selected, but
            // nothing is decided here.
            const row = await adapter.findOne<Row>({
                model,
                where: [...key, ...live(now)],
            });
            if (!row) return null;

            // This is the claim, and it is a single guarded statement. Every
            // liveness predicate is repeated inside the guard, so the read
            // above cannot go stale between the two: concurrent callers all
            // target the same row, the database serializes them, and exactly
            // one sees an affected count of 1. The losers get 0 and return
            // null, which is the correct answer — someone else redeemed it.
            const affected = affectedRows(
                await adapter.updateMany({
                    model,
                    where: [{ field: "challengeId", value: row.challengeId }, ...live(now)],
                    update: { consumedAt: new Date(now) },
                }),
            );
            if (affected !== 1) return null;

            // The winner already holds the row it just claimed, so there is
            // no read-back to race against. Only `consumedAt` changed, and we
            // are the ones who set it.
            return toChallenge({ ...row, consumedAt: new Date(now) });
        },

        async registerFailedAttempt(query: {
            email: string;
            purpose: Purpose;
            now: number;
        }): Promise<FailedAttemptOutcome> {
            const { email, purpose, now } = query;

            // Deliberately not filtered by remaining budget. A challenge
            // whose attempts are spent has not gone anywhere, and reporting
            // it as absent would turn "no attempts left" into "wrong code" on
            // every submission after the last one, looping the user forever.
            const candidates = await adapter.findMany<Row>({
                model,
                where: [
                    { field: "email", value: email },
                    { field: "purpose", value: purpose },
                    ...present(now),
                ],
            });
            if (candidates.length === 0) return { found: false, remaining: 0 };

            // Normally exactly one challenge is live per address. Spending
            // one attempt against each keeps the pathological case — a race
            // between two issued challenges — from handing an attacker a
            // budget per row.
            let found = false;
            let remaining = 0;
            for (const candidate of candidates) {
                const left = await spendAttempt(candidate.challengeId, now);
                if (left === null) continue;
                found = true;
                remaining = Math.max(remaining, left);
            }

            return { found, remaining };
        },

        async delete(id: string): Promise<void> {
            await adapter.delete({
                model,
                where: [{ field: "challengeId", value: id }],
            });
        },

        async countIssuedSince(query: {
            email: string;
            purpose: Purpose;
            since: number;
        }): Promise<number> {
            // Counts consumed and expired rows too. Excluding them would let
            // a user reset their own send quota by redeeming a code, which
            // would stop the per-address cap being a cap.
            return adapter.count({
                model,
                where: [
                    { field: "email", value: query.email },
                    { field: "purpose", value: query.purpose },
                    { field: "createdAt", operator: "gte", value: new Date(query.since) },
                ],
            });
        },

        async deleteExpired(now: number): Promise<number> {
            return adapter.deleteMany({
                model,
                where: [{ field: "expiresAt", operator: "lte", value: new Date(now) }],
            });
        },
    };
}
