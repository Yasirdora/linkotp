import { test } from "node:test";
import assert from "node:assert/strict";

import { createLinkOtp } from "../src/core.ts";
import { normalizeCode, normalizeEmail, DEFAULT_CODE_ALPHABET } from "../src/config.ts";
import { createMemoryStore } from "../src/stores/memory.ts";
import { SECRET, BASE_URL } from "./helpers.ts";

const base = () => ({
    secret: SECRET,
    baseUrl: BASE_URL,
    store: createMemoryStore(),
    mailer: async () => {},
});

function rejects(overrides: Record<string, unknown>, pattern: RegExp): void {
    assert.throws(() => createLinkOtp({ ...base(), ...overrides } as never), pattern);
}

test("a weak or missing secret is rejected at construction", () => {
    rejects({ secret: "short" }, /at least 32 characters/);
    rejects({ secret: undefined }, /at least 32 characters/);
    rejects({ secret: 12345 }, /at least 32 characters/);
});

test("a non-https baseUrl is rejected outside local development", () => {
    rejects({ baseUrl: "http://example.com" }, /must be https/);
    rejects({ baseUrl: "not-a-url" }, /not a valid absolute URL/);
    assert.doesNotThrow(() => createLinkOtp({ ...base(), baseUrl: "http://localhost:3000" }));
    assert.doesNotThrow(() => createLinkOtp({ ...base(), baseUrl: "http://127.0.0.1:8787" }));
});

test("a token below 128 bits of entropy is rejected", () => {
    // Ten alphanumerics is about 60 bits: fine for a typed code, far too weak
    // for a bearer credential that travels in a URL.
    rejects({ token: { length: 10 } }, /below the 128-bit minimum/);
    rejects({ token: { length: 4, alphabet: "0123456789" } }, /below the 128-bit minimum/);
    assert.doesNotThrow(() => createLinkOtp({ ...base(), token: { length: 22 } }));
});

test("a code below 20 bits of entropy is rejected", () => {
    rejects({ code: { length: 3, alphabet: "0123456789" } }, /below the 20-bit minimum/);
});

test("a duplicated alphabet character is rejected", () => {
    rejects({ code: { alphabet: "AABCDEFG" } }, /duplicate characters/);
});

test("out-of-range lifetimes and attempt budgets are rejected", () => {
    rejects({ ttlSeconds: 30 }, /between 60 and 86400/);
    rejects({ ttlSeconds: 90_000 }, /between 60 and 86400/);
    rejects({ maxAttempts: 0 }, /between 1 and 100/);
    rejects({ verifyPath: "https://evil.test" }, /absolute same-origin path/);
    rejects({ verifyPath: "//evil.test" }, /absolute same-origin path/);
});

test("the resolved config never retains the plaintext secret", () => {
    const auth = createLinkOtp(base());
    assert.ok(
        !JSON.stringify(auth.config).includes(SECRET),
        "the secret leaked through config serialization",
    );
    assert.ok(!JSON.stringify(auth).includes(SECRET), "the secret leaked through the instance");
});

test("normalizeEmail lowercases and trims", () => {
    assert.equal(normalizeEmail("  Person@Example.COM "), "person@example.com");
    assert.equal(normalizeEmail("a.b+tag@sub.example.co.uk"), "a.b+tag@sub.example.co.uk");
});

test("normalizeEmail rejects malformed input", () => {
    const bad: unknown[] = [
        "",
        "   ",
        "no-at-sign",
        "no@domain",
        "@example.com",
        "person@",
        "two@@example.com",
        "person@example .com",
        "person@exam ple.com",
        "person\n@example.com",
        "person\u0000@example.com",
        `${"a".repeat(250)}@example.com`,
        null,
        undefined,
        42,
    ];
    for (const value of bad) {
        assert.equal(normalizeEmail(value), null, `should reject ${JSON.stringify(value)}`);
    }
});

test("normalizeEmail does not apply provider-specific dot or tag stripping", () => {
    // Gmail ignores dots; almost nobody else does. Stripping them here would
    // silently merge distinct people on a corporate domain into one account.
    assert.equal(normalizeEmail("first.last@company.com"), "first.last@company.com");
    assert.equal(normalizeEmail("user+billing@company.com"), "user+billing@company.com");
});

test("normalizeCode tolerates how people actually type codes", () => {
    assert.equal(normalizeCode("k7 m2-9q", DEFAULT_CODE_ALPHABET), "K7M29Q");
    assert.equal(normalizeCode("  k7m29q  ", DEFAULT_CODE_ALPHABET), "K7M29Q");
    assert.equal(normalizeCode("K7M29Q", DEFAULT_CODE_ALPHABET), "K7M29Q");
    // Characters outside the alphabet are dropped rather than mapped, so a
    // mistyped O never silently becomes a 0.
    assert.equal(normalizeCode("K7M2O0", DEFAULT_CODE_ALPHABET), "K7M2");
    assert.equal(normalizeCode(null, DEFAULT_CODE_ALPHABET), "");
});
