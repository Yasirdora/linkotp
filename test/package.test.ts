import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";

/**
 * Packaging checks.
 *
 * Unit tests run against `src/`, which says nothing about whether the
 * published artifact actually loads. These exercise `dist/` the way a consumer
 * would, through both module systems, and are skipped when the build has not
 * run so `npm test` stays fast in a watch loop.
 */

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Resolves a path in `dist/` to something `import()` will actually accept.
 *
 * A bare absolute path works on POSIX and fails on Windows, where the ESM
 * loader reads the drive letter as a URL scheme and rejects it with
 * `ERR_UNSUPPORTED_ESM_URL_SCHEME: Received protocol 'd:'`. Only CI on
 * windows-latest catches this, which is the entire argument for having it in
 * the matrix.
 */
const dist = (path: string): string => pathToFileURL(resolve(root, path)).href;
const built = existsSync(resolve(root, "dist/index.js"));

const requireCjs = createRequire(import.meta.url);

test("the ESM build exposes the documented surface", { skip: !built && "run `npm run build` first" }, async () => {
    const mod = await import(dist("dist/index.js"));

    for (const name of [
        "createLinkOtp",
        "LinkOtpError",
        "normalizeEmail",
        "normalizeCode",
        "randomString",
        "timingSafeEqual",
        "entropyBits",
        "createMemoryRateLimiter",
        "renderDefaultTemplate",
        "RECOMMENDED_HEADERS",
        "DEFAULT_CODE_ALPHABET",
        "DEFAULT_TOKEN_LENGTH",
    ]) {
        assert.equal(typeof mod[name] !== "undefined", true, `missing export: ${name}`);
    }
});

test("the subpath entries resolve", { skip: !built && "run `npm run build` first" }, async () => {
    const stores = await import(dist("dist/stores/index.js"));
    assert.equal(typeof stores.createMemoryStore, "function");
    assert.equal(typeof stores.createSqlStore, "function");
    assert.equal(typeof stores.schemaFor, "function");

    const http = await import(dist("dist/http/index.js"));
    assert.equal(typeof http.createHandler, "function");
    assert.equal(typeof http.sanitizeRedirect, "function");

    const testing = await import(dist("dist/testing/index.js"));
    assert.equal(typeof testing.checkStoreConformance, "function");

    // This one also proves the optional peer resolves at runtime: the module
    // imports `better-auth/api` and `better-auth/cookies` at load time.
    const betterAuth = await import(dist("dist/better-auth/index.js"));
    assert.equal(typeof betterAuth.linkotp, "function");
    assert.equal(typeof betterAuth.createBetterAuthStore, "function");
    assert.equal(typeof betterAuth.linkotpSchema, "function");

    // The client half must load with *no* better-auth import of its own: it
    // ships to the browser, and pulling the server plugin in would drag
    // `better-auth/api` and linkotp's protocol core along with it.
    const client = await import(dist("dist/better-auth/client.js"));
    assert.equal(typeof client.linkotpClient, "function");
    assert.equal(client.linkotpClient().id, "linkotp");
});

test("the Better Auth entry is ESM-only, deliberately", () => {
    const pkg = requireCjs(resolve(root, "package.json")) as {
        exports: Record<string, Record<string, string>>;
    };

    // Better Auth is ESM-only — its own package.json publishes no `require`
    // condition — so a CommonJS consumer cannot use this entry point at all.
    // Advertising one would resolve fine and then fail at load on every Node
    // before 22.12, which is a worse error than not offering it. The other
    // entries stay dual-published because they import nothing.
    assert.equal(pkg.exports["./better-auth"]!["require"], undefined);
    assert.equal(pkg.exports["./better-auth/client"]!["require"], undefined);
    assert.equal(typeof pkg.exports["./better-auth"]!["import"], "string");
    assert.equal(typeof pkg.exports["."]!["require"], "string");
});

test("the CommonJS build loads under require()", { skip: !built && "run `npm run build` first" }, () => {
    const mod = requireCjs(resolve(root, "dist/cjs/index.js")) as Record<string, unknown>;
    assert.equal(typeof mod.createLinkOtp, "function");

    const stores = requireCjs(resolve(root, "dist/cjs/stores/index.js")) as Record<string, unknown>;
    assert.equal(typeof stores.createMemoryStore, "function");
});

test("the ESM build actually runs end to end", { skip: !built && "run `npm run build` first" }, async () => {
    const { createLinkOtp } = await import(dist("dist/index.js"));
    const { createMemoryStore } = await import(dist("dist/stores/index.js"));

    const sent: Array<{ text: string }> = [];
    const auth = createLinkOtp({
        secret: "packaging-test-secret-at-least-32-characters",
        baseUrl: "https://example.com",
        store: createMemoryStore(),
        minimumStartDurationMs: 0,
        mailer: async (message: { text: string }) => {
            sent.push(message);
        },
    });

    await auth.start({ email: "person@example.com" });
    const token = /token=([A-Za-z0-9]+)/.exec(sent[0]!.text)![1]!;
    const identity = await auth.verifyToken({ token });

    assert.equal(identity.email, "person@example.com");
    assert.equal(identity.via, "link");
});

test("declaration files ship alongside every entry point", { skip: !built && "run `npm run build` first" }, () => {
    for (const dts of [
        "dist/index.d.ts",
        "dist/stores/index.d.ts",
        "dist/http/index.d.ts",
        "dist/testing/index.d.ts",
        "dist/better-auth/index.d.ts",
        "dist/better-auth/client.d.ts",
    ]) {
        assert.ok(existsSync(resolve(root, dts)), `missing ${dts}`);
    }
});

test("the published package declares no runtime dependencies", () => {
    const pkg = requireCjs(resolve(root, "package.json")) as {
        dependencies?: Record<string, string>;
        peerDependencies?: Record<string, string>;
        peerDependenciesMeta?: Record<string, { optional?: boolean }>;
        devDependencies?: Record<string, string>;
    };

    // Asserted as present-and-empty, not merely absent: `npm install` strips
    // an empty `dependencies` object, and the field is a deliberate statement
    // that the emptiness is intended rather than incidental.
    assert.deepEqual(pkg.dependencies, {}, "linkotp must stay dependency-free");

    // Every peer must be optional. An optional peer installs nothing for a
    // user who never imports the entry point that needs it, so the
    // zero-dependency guarantee survives; a *required* peer would quietly
    // break it, which is why this asserts the flag rather than the absence.
    for (const name of Object.keys(pkg.peerDependencies ?? {})) {
        assert.equal(
            pkg.peerDependenciesMeta?.[name]?.optional,
            true,
            `peer dependency ${name} must be marked optional`,
        );
    }
    assert.deepEqual(Object.keys(pkg.peerDependencies ?? {}), ["better-auth"]);

    // The compiler, plus the optional peer the plugin is typed and tested
    // against. Tests use node:test, the build is plain tsc, and the SQL suite
    // runs on node:sqlite.
    assert.deepEqual(Object.keys(pkg.devDependencies ?? {}).sort(), ["better-auth", "typescript"]);
});
