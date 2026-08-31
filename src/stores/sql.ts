/**
 * SQL store.
 *
 * Speaks to any SQL database through a two-method driver, so the same code
 * runs on Cloudflare D1, Postgres, libSQL/Turso, better-sqlite3, MySQL, or
 * anything else you can wrap in `all` and `run`. No ORM, no query builder, no
 * dependency.
 */

import type {
    Challenge,
    ConsumeQuery,
    FailedAttemptOutcome,
    Purpose,
    TokenStore,
} from "../types.ts";

/** Minimal surface linkotp needs from a database client. */
export interface SqlDriver {
    /** Runs a query and returns every row. */
    all<T extends Record<string, unknown>>(sql: string, params: readonly unknown[]): Promise<T[]>;
    /** Runs a statement and reports how many rows it changed. */
    run(sql: string, params: readonly unknown[]): Promise<{ rowsAffected: number }>;
}

export type SqlDialect = "sqlite" | "postgres" | "mysql";

export interface SqlStoreOptions {
    readonly driver: SqlDriver;
    /** @default "sqlite" */
    readonly dialect?: SqlDialect;
    /** @default "linkotp_challenge" */
    readonly table?: string;
}

/**
 * Table and schema identifiers cannot be parameterized in SQL, so a configured
 * table name is interpolated directly into every statement. It is validated
 * against a strict identifier grammar first. Without this check, a table name
 * sourced from configuration or an environment variable would be a clean
 * injection point.
 */
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$/;

/** Dialects whose UPDATE supports RETURNING, making claim-and-read one statement. */
const RETURNING_DIALECTS: ReadonlySet<SqlDialect> = new Set<SqlDialect>(["sqlite", "postgres"]);

interface Row extends Record<string, unknown> {
    id: string;
    email: string;
    purpose: string;
    code_hash: string;
    token_hash: string;
    binding_hash: string | null;
    metadata: string | null;
    attempts: number | string;
    max_attempts: number | string;
    created_at: number | string;
    expires_at: number | string;
    consumed_at: number | string | null;
}

/**
 * Normalizes a driver row into a Challenge.
 *
 * Integer columns come back as JavaScript numbers from SQLite drivers but as
 * strings from most Postgres drivers, which return BIGINT as a string to avoid
 * precision loss. Coercing here means callers never have to care which
 * database they are on.
 */
function toChallenge(row: Row): Challenge {
    const num = (value: number | string): number =>
        typeof value === "number" ? value : Number(value);

    let metadata: Readonly<Record<string, unknown>> | null = null;
    if (row.metadata !== null && row.metadata !== undefined) {
        metadata =
            typeof row.metadata === "string"
                ? (JSON.parse(row.metadata) as Record<string, unknown>)
                : (row.metadata as Record<string, unknown>);
    }

    return Object.freeze({
        id: row.id,
        email: row.email,
        purpose: row.purpose as Purpose,
        codeHash: row.code_hash,
        tokenHash: row.token_hash,
        bindingHash: row.binding_hash,
        metadata,
        attempts: num(row.attempts),
        maxAttempts: num(row.max_attempts),
        createdAt: num(row.created_at),
        expiresAt: num(row.expires_at),
        consumedAt: row.consumed_at === null ? null : num(row.consumed_at),
    });
}

interface Query {
    readonly params: unknown[];
    bind(value: unknown): string;
}

export function createSqlStore(options: SqlStoreOptions): TokenStore {
    const { driver } = options;
    const dialect: SqlDialect = options.dialect ?? "sqlite";
    const table = options.table ?? "linkotp_challenge";

    if (!IDENTIFIER.test(table)) {
        throw new Error(
            `linkotp: table name ${JSON.stringify(table)} is not a valid SQL identifier. ` +
                "Use letters, digits, and underscores, optionally schema-qualified.",
        );
    }

    const supportsReturning = RETURNING_DIALECTS.has(dialect);

    /**
     * Ties placeholder generation to parameter collection.
     *
     * Postgres numbers its placeholders while everyone else uses positional
     * `?`, and hand-maintaining a counter alongside a separate params array is
     * a standing invitation to desync them, which silently binds the wrong
     * value to the wrong column. Here `bind` is the only way to produce a
     * placeholder, and it appends the value in the same call, so the two
     * cannot drift.
     */
    function query(): Query {
        const params: unknown[] = [];
        return {
            params,
            bind(value: unknown): string {
                params.push(value);
                return dialect === "postgres" ? `$${params.length}` : "?";
            },
        };
    }

    /**
     * Performs the guarded UPDATE, then materializes the claimed row.
     *
     * `buildUpdate` must emit a statement whose WHERE clause carries every
     * liveness predicate. `buildReadBack` is consulted only on dialects
     * without RETURNING, and must identify the same row by its own key.
     */
    async function claim(
        buildUpdate: (q: Query) => string,
        buildReadBack: (q: Query) => string,
    ): Promise<Challenge | null> {
        const update = query();
        const sql = buildUpdate(update);

        if (supportsReturning) {
            const rows = await driver.all<Row>(`${sql} RETURNING *`, update.params);
            return rows.length > 0 ? toChallenge(rows[0]!) : null;
        }

        // MySQL has no RETURNING. The claim is still atomic, because the guard
        // lives inside the UPDATE and the engine holds a row lock for its
        // duration. Only the read-back is a second statement, and it is scoped
        // to the row this caller just claimed.
        const result = await driver.run(sql, update.params);
        if (result.rowsAffected !== 1) return null;

        const read = query();
        const rows = await driver.all<Row>(buildReadBack(read), read.params);
        return rows.length > 0 ? toChallenge(rows[0]!) : null;
    }

    return {
        async insert(challenge: Challenge): Promise<void> {
            const q = query();
            const values = [
                challenge.id,
                challenge.email,
                challenge.purpose,
                challenge.codeHash,
                challenge.tokenHash,
                challenge.bindingHash,
                challenge.metadata === null ? null : JSON.stringify(challenge.metadata),
                challenge.attempts,
                challenge.maxAttempts,
                challenge.createdAt,
                challenge.expiresAt,
                challenge.consumedAt,
            ].map((value) => q.bind(value));

            await driver.run(
                `INSERT INTO ${table} (
                    id, email, purpose, code_hash, token_hash, binding_hash,
                    metadata, attempts, max_attempts, created_at, expires_at, consumed_at
                 ) VALUES (${values.join(", ")})`,
                q.params,
            );
        },

        async consume(request: ConsumeQuery): Promise<Challenge | null> {
            // One guarded UPDATE. The WHERE clause is the compare and the SET
            // is the swap; the database performs both under a single row lock,
            // so two concurrent callers cannot both succeed. Every liveness
            // predicate sits inside the guard, never in calling code.
            const live = (q: Query): string =>
                `consumed_at IS NULL AND expires_at > ${q.bind(request.now)} ` +
                "AND attempts < max_attempts";

            if (request.by === "token") {
                return claim(
                    (q) =>
                        `UPDATE ${table} SET consumed_at = ${q.bind(request.now)} ` +
                        `WHERE token_hash = ${q.bind(request.tokenHash)} AND ${live(q)}`,
                    (q) =>
                        `SELECT * FROM ${table} WHERE token_hash = ${q.bind(request.tokenHash)} ` +
                        `AND consumed_at = ${q.bind(request.now)} LIMIT 1`,
                );
            }

            return claim(
                (q) =>
                    `UPDATE ${table} SET consumed_at = ${q.bind(request.now)} ` +
                    `WHERE email = ${q.bind(request.email)} ` +
                    `AND purpose = ${q.bind(request.purpose)} ` +
                    `AND code_hash = ${q.bind(request.codeHash)} AND ${live(q)}`,
                (q) =>
                    `SELECT * FROM ${table} WHERE email = ${q.bind(request.email)} ` +
                    `AND purpose = ${q.bind(request.purpose)} ` +
                    `AND code_hash = ${q.bind(request.codeHash)} ` +
                    `AND consumed_at = ${q.bind(request.now)} LIMIT 1`,
            );
        },

        async registerFailedAttempt(request: {
            email: string;
            purpose: Purpose;
            now: number;
        }): Promise<FailedAttemptOutcome> {
            const update = query();
            await driver.run(
                `UPDATE ${table} SET attempts = attempts + 1 ` +
                    `WHERE email = ${update.bind(request.email)} ` +
                    `AND purpose = ${update.bind(request.purpose)} ` +
                    `AND consumed_at IS NULL AND expires_at > ${update.bind(request.now)} ` +
                    "AND attempts < max_attempts",
                update.params,
            );

            // Advisory only: it feeds the "N attempts remaining" message.
            // Enforcement lives in the consume guard, which re-evaluates
            // attempts against max_attempts on every claim, so a stale read
            // here can never let an exhausted challenge through.
            //
            // The count deliberately omits the attempts predicate. A challenge
            // whose budget is spent has not gone anywhere, and reporting it as
            // absent would turn "no attempts left" into "wrong code" on every
            // submission after the last one.
            const read = query();
            const rows = await driver.all<{
                live: number | string;
                remaining: number | string | null;
            }>(
                `SELECT COUNT(*) AS live, MAX(max_attempts - attempts) AS remaining ` +
                    `FROM ${table} WHERE email = ${read.bind(request.email)} ` +
                    `AND purpose = ${read.bind(request.purpose)} ` +
                    `AND consumed_at IS NULL AND expires_at > ${read.bind(request.now)}`,
                read.params,
            );

            const row = rows[0];
            const found = Number(row?.live ?? 0) > 0;
            const remaining = row?.remaining;
            return {
                found,
                remaining:
                    remaining === null || remaining === undefined
                        ? 0
                        : Math.max(0, Number(remaining)),
            };
        },

        async delete(id: string): Promise<void> {
            const q = query();
            await driver.run(`DELETE FROM ${table} WHERE id = ${q.bind(id)}`, q.params);
        },

        async countIssuedSince(request: {
            email: string;
            purpose: Purpose;
            since: number;
        }): Promise<number> {
            const q = query();
            const rows = await driver.all<{ total: number | string }>(
                `SELECT COUNT(*) AS total FROM ${table} ` +
                    `WHERE email = ${q.bind(request.email)} ` +
                    `AND purpose = ${q.bind(request.purpose)} ` +
                    `AND created_at >= ${q.bind(request.since)}`,
                q.params,
            );
            return Number(rows[0]?.total ?? 0);
        },

        async deleteExpired(now: number): Promise<number> {
            const q = query();
            const result = await driver.run(
                `DELETE FROM ${table} WHERE expires_at <= ${q.bind(now)}`,
                q.params,
            );
            return result.rowsAffected;
        },
    };
}

/**
 * Schema for the challenge table.
 *
 * The unique constraint on `token_hash` is not decorative: it is the last line
 * of defence against a token collision silently overwriting a live challenge.
 * At 286 bits of entropy a collision will not happen, but a misconfigured
 * `token.length` could shrink that, and the constraint turns a silent
 * authentication bug into a loud insert failure.
 *
 * The indexes cover the two hot lookups, `token_hash` for the link path and
 * `(email, purpose)` for the code path, plus `expires_at` for sweeping.
 */
export function schemaFor(dialect: SqlDialect, table = "linkotp_challenge"): string {
    if (!IDENTIFIER.test(table)) {
        throw new Error(`linkotp: invalid table name ${JSON.stringify(table)}`);
    }

    const types =
        dialect === "postgres"
            ? { text: "TEXT", bigint: "BIGINT", int: "INTEGER" }
            : dialect === "mysql"
              ? { text: "VARCHAR(255)", bigint: "BIGINT", int: "INT" }
              : { text: "TEXT", bigint: "INTEGER", int: "INTEGER" };

    return `CREATE TABLE IF NOT EXISTS ${table} (
    id            ${types.text} PRIMARY KEY,
    email         ${types.text} NOT NULL,
    purpose       ${types.text} NOT NULL,
    code_hash     ${types.text} NOT NULL,
    token_hash    ${types.text} NOT NULL UNIQUE,
    binding_hash  ${types.text},
    metadata      TEXT,
    attempts      ${types.int}    NOT NULL DEFAULT 0,
    max_attempts  ${types.int}    NOT NULL,
    created_at    ${types.bigint} NOT NULL,
    expires_at    ${types.bigint} NOT NULL,
    consumed_at   ${types.bigint}
);

CREATE INDEX IF NOT EXISTS ${table}_token_idx  ON ${table} (token_hash);
CREATE INDEX IF NOT EXISTS ${table}_lookup_idx ON ${table} (email, purpose);
CREATE INDEX IF NOT EXISTS ${table}_expiry_idx ON ${table} (expires_at);`;
}
