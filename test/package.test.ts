import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
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
const built = existsSync(resolve(root, "dist/index.js"));

const requireCjs = createRequire(import.meta.url);

test("the ESM build exposes the documented surface", { skip: !built && "run `npm run build` first" }, async () => {
    const mod = await import(resolve(root, "dist/index.js"));

    for (const name of [
        "createOtpLink",
        "OtpLinkError",
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
    const stores = await import(resolve(root, "dist/stores/index.js"));
    assert.equal(typeof stores.createMemoryStore, "function");
    assert.equal(typeof stores.createSqlStore, "function");
    assert.equal(typeof stores.schemaFor, "function");

    const http = await import(resolve(root, "dist/http/index.js"));
    assert.equal(typeof http.createHandler, "function");
    assert.equal(typeof http.sanitizeRedirect, "function");

    const testing = await import(resolve(root, "dist/testing/index.js"));
    assert.equal(typeof testing.checkStoreConformance, "function");
});

test("the CommonJS build loads under require()", { skip: !built && "run `npm run build` first" }, () => {
    const mod = requireCjs(resolve(root, "dist/cjs/index.js")) as Record<string, unknown>;
    assert.equal(typeof mod.createOtpLink, "function");

    const stores = requireCjs(resolve(root, "dist/cjs/stores/index.js")) as Record<string, unknown>;
    assert.equal(typeof stores.createMemoryStore, "function");
});

test("the ESM build actually runs end to end", { skip: !built && "run `npm run build` first" }, async () => {
    const { createOtpLink } = await import(resolve(root, "dist/index.js"));
    const { createMemoryStore } = await import(resolve(root, "dist/stores/index.js"));

    const sent: Array<{ text: string }> = [];
    const auth = createOtpLink({
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
    ]) {
        assert.ok(existsSync(resolve(root, dts)), `missing ${dts}`);
    }
});

test("the published package declares no runtime dependencies", () => {
    const pkg = requireCjs(resolve(root, "package.json")) as {
        dependencies?: Record<string, string>;
        peerDependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
    };

    assert.deepEqual(pkg.dependencies ?? {}, {}, "otplink must stay dependency-free");
    assert.deepEqual(pkg.peerDependencies ?? {}, {}, "no peer dependencies either");
    // One devDependency, and it is the compiler. Tests use node:test, the
    // build is plain tsc, and the SQL suite runs on node:sqlite.
    assert.deepEqual(Object.keys(pkg.devDependencies ?? {}), ["typescript"]);
});
