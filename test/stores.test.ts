import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";

import { createMemoryStore } from "../src/stores/memory.ts";
import { createSqlStore, schemaFor, type SqlDriver } from "../src/stores/sql.ts";
import { checkStoreConformance } from "../src/testing/conformance.ts";
import type { Challenge } from "../src/types.ts";

/**
 * Adapts node:sqlite to the SqlDriver interface.
 *
 * Testing the SQL store against a real engine rather than a mock is the only
 * way to know the guarded UPDATE actually behaves as claimed. Node ships
 * SQLite, so this costs no dependency.
 */
function sqliteDriver(): SqlDriver & { close(): void } {
    const db = new DatabaseSync(":memory:");
    for (const statement of schemaFor("sqlite").split(";")) {
        if (statement.trim()) db.exec(statement);
    }
    return {
        async all<T extends Record<string, unknown>>(sql: string, params: readonly unknown[]) {
            return db.prepare(sql).all(...params) as T[];
        },
        async run(sql: string, params: readonly unknown[]) {
            const info = db.prepare(sql).run(...params);
            return { rowsAffected: Number(info.changes) };
        },
        close: () => db.close(),
    };
}

test("the memory store satisfies the conformance suite", async () => {
    const report = await checkStoreConformance({ createStore: () => createMemoryStore() });
    assert.ok(report.passed, report.summary);
    assert.ok(report.results.length >= 15);
});

test("the SQL store satisfies the conformance suite on SQLite", async () => {
    const open: Array<{ close(): void }> = [];
    const report = await checkStoreConformance({
        createStore: () => {
            const driver = sqliteDriver();
            open.push(driver);
            return createSqlStore({ driver, dialect: "sqlite" });
        },
    });
    for (const driver of open) driver.close();
    assert.ok(report.passed, report.summary);
});

test("the SQL store satisfies the conformance suite without RETURNING", async () => {
    // The mysql dialect takes the two-statement claim-then-read path. Running
    // it against SQLite exercises that code without needing a MySQL server:
    // the generated SQL is portable, only the RETURNING branch differs.
    const open: Array<{ close(): void }> = [];
    const report = await checkStoreConformance({
        createStore: () => {
            const driver = sqliteDriver();
            open.push(driver);
            return createSqlStore({ driver, dialect: "mysql" });
        },
    });
    for (const driver of open) driver.close();
    assert.ok(report.passed, report.summary);
});

test("the conformance suite catches a non-atomic consume", async () => {
    // A store that reads, checks, then writes. This is the mistake the suite
    // exists to find, so the suite must actually fail on it.
    function brokenStore() {
        const inner = createMemoryStore();
        return {
            ...inner,
            async consume(query: Parameters<typeof inner.consume>[0]) {
                const peek = await inner.consume(query);
                if (peek) {
                    // Re-open the row, reintroducing the race a guarded UPDATE
                    // would have prevented.
                    await inner.insert({ ...peek, consumedAt: null, id: `${peek.id}_x` });
                    await inner.delete(peek.id);
                    const reopened: Challenge = { ...peek, consumedAt: null };
                    return reopened;
                }
                return null;
            },
        };
    }

    const report = await checkStoreConformance({ createStore: brokenStore });
    assert.ok(!report.passed, "the suite passed a store that reopens consumed rows");
    assert.match(report.summary, /consumed only once|concurrent/);
});

test("postgres placeholders stay aligned with their parameters", async () => {
    const seen: Array<{ sql: string; params: readonly unknown[] }> = [];
    const driver: SqlDriver = {
        async all(sql, params) {
            seen.push({ sql, params });
            return [];
        },
        async run(sql, params) {
            seen.push({ sql, params });
            return { rowsAffected: 0 };
        },
    };

    const store = createSqlStore({ driver, dialect: "postgres" });
    await store.insert({
        id: "abc",
        email: "person@example.com",
        purpose: "sign-in",
        codeHash: "ch",
        tokenHash: "th",
        bindingHash: null,
        metadata: { a: 1 },
        attempts: 0,
        maxAttempts: 5,
        createdAt: 1,
        expiresAt: 2,
        consumedAt: null,
    });

    const insert = seen[0]!;
    // Twelve columns, numbered $1..$12 in order, with twelve bound values.
    assert.equal(insert.params.length, 12);
    assert.ok(insert.sql.includes("$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12"));
    assert.equal(insert.params[0], "abc");
    assert.equal(insert.params[11], null);

    seen.length = 0;
    await store.consume({ by: "token", tokenHash: "th", now: 99 });
    const update = seen[0]!;
    // consumed_at = $1, token_hash = $2, expires_at > $3.
    assert.deepEqual(update.params, [99, "th", 99]);
    assert.ok(update.sql.includes("SET consumed_at = $1"));
    assert.ok(update.sql.includes("token_hash = $2"));
    assert.ok(update.sql.includes("expires_at > $3"));
    assert.ok(update.sql.endsWith("RETURNING *"));
});

test("the consume guard carries every liveness predicate", async () => {
    const statements: string[] = [];
    const driver: SqlDriver = {
        async all(sql) {
            statements.push(sql);
            return [];
        },
        async run(sql) {
            statements.push(sql);
            return { rowsAffected: 0 };
        },
    };

    const store = createSqlStore({ driver, dialect: "sqlite" });
    await store.consume({ by: "token", tokenHash: "th", now: 5 });
    await store.consume({
        by: "code",
        email: "person@example.com",
        purpose: "sign-in",
        codeHash: "ch",
        now: 5,
    });

    for (const sql of statements) {
        assert.ok(sql.startsWith("UPDATE"), "the claim must be an UPDATE, never a SELECT");
        assert.ok(sql.includes("consumed_at IS NULL"), "missing the single-use predicate");
        assert.ok(sql.includes("expires_at >"), "missing the expiry predicate");
        assert.ok(sql.includes("attempts < max_attempts"), "missing the attempt predicate");
    }
});

test("an invalid table name is rejected rather than interpolated", async () => {
    const driver: SqlDriver = {
        async all() {
            return [];
        },
        async run() {
            return { rowsAffected: 0 };
        },
    };

    for (const table of [
        "users; DROP TABLE users--",
        "tbl WHERE 1=1",
        "1_starts_with_digit",
        "has-a-hyphen",
        "has space",
        "",
    ]) {
        assert.throws(
            () => createSqlStore({ driver, table }),
            /not a valid SQL identifier/,
            `should reject ${JSON.stringify(table)}`,
        );
        assert.throws(() => schemaFor("sqlite", table), /invalid table name/);
    }

    assert.doesNotThrow(() => createSqlStore({ driver, table: "auth.linkotp_challenge" }));
});

test("the schema constrains token_hash to be unique", () => {
    for (const dialect of ["sqlite", "postgres", "mysql"] as const) {
        const ddl = schemaFor(dialect);
        assert.match(ddl, /token_hash\s+\S+\s+NOT NULL UNIQUE/);
        assert.ok(ddl.includes("linkotp_challenge_token_idx"));
        assert.ok(ddl.includes("linkotp_challenge_lookup_idx"));
        assert.ok(ddl.includes("linkotp_challenge_expiry_idx"));
    }
});

test("the SQL store round-trips a challenge through a real database", async () => {
    const driver = sqliteDriver();
    const store = createSqlStore({ driver, dialect: "sqlite" });

    const challenge: Challenge = {
        id: "ch_1",
        email: "person@example.com",
        purpose: "sign-in",
        codeHash: "code-digest",
        tokenHash: "token-digest",
        bindingHash: "binding-digest",
        metadata: { plan: "pro", seats: 3 },
        attempts: 0,
        maxAttempts: 5,
        createdAt: 1_000,
        expiresAt: 2_000,
        consumedAt: null,
    };
    await store.insert(challenge);

    const claimed = await store.consume({ by: "token", tokenHash: "token-digest", now: 1_500 });
    assert.ok(claimed);
    assert.equal(claimed.id, "ch_1");
    assert.equal(claimed.bindingHash, "binding-digest");
    assert.deepEqual(claimed.metadata, { plan: "pro", seats: 3 });
    assert.equal(claimed.consumedAt, 1_500);

    driver.close();
});

test("the unique constraint rejects a duplicate token hash", async () => {
    const driver = sqliteDriver();
    const store = createSqlStore({ driver, dialect: "sqlite" });

    const make = (id: string): Challenge => ({
        id,
        email: "person@example.com",
        purpose: "sign-in",
        codeHash: `code-${id}`,
        tokenHash: "identical-token",
        bindingHash: null,
        metadata: null,
        attempts: 0,
        maxAttempts: 5,
        createdAt: 1_000,
        expiresAt: 2_000,
        consumedAt: null,
    });

    await store.insert(make("a"));
    // A collision must fail loudly rather than silently overwrite a live row.
    await assert.rejects(() => store.insert(make("b")));

    driver.close();
});
