import { test } from "node:test";
import assert from "node:assert/strict";

import { createHasher, entropyBits, randomString, timingSafeEqual } from "../src/crypto.ts";

test("randomString honours length and alphabet", () => {
    const value = randomString(48, "abc");
    assert.equal(value.length, 48);
    assert.match(value, /^[abc]+$/);
});

test("randomString rejects a biased or degenerate alphabet", () => {
    assert.throws(() => randomString(8, "a"), /between 2 and 256/);
    assert.throws(() => randomString(8, "aab"), /duplicate/);
    assert.throws(() => randomString(0, "ab"), /positive integer/);
});

test("randomString is uniform over its alphabet", () => {
    // Rejection sampling should keep every character within a few percent of
    // its expected share. A naive `byte % 62` skews the first eight
    // characters by about 25%, which this margin catches decisively.
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const draws = 62_000;
    const counts = new Map<string, number>();

    for (const char of randomString(draws, alphabet)) {
        counts.set(char, (counts.get(char) ?? 0) + 1);
    }

    const expected = draws / alphabet.length;
    for (const char of alphabet) {
        const seen = counts.get(char) ?? 0;
        const drift = Math.abs(seen - expected) / expected;
        assert.ok(drift < 0.2, `${char} drifted ${(drift * 100).toFixed(1)}% from uniform`);
    }
});

test("randomString does not repeat itself", () => {
    const seen = new Set(Array.from({ length: 500 }, () => randomString(24, "abcdef0123456789")));
    assert.equal(seen.size, 500);
});

test("entropyBits matches the documented figures", () => {
    assert.ok(Math.abs(entropyBits(6, 32) - 30) < 0.01);
    assert.ok(Math.abs(entropyBits(48, 62) - 285.9) < 0.1);
    // The six-digit code the whole design argues against.
    assert.ok(Math.abs(entropyBits(6, 10) - 19.93) < 0.01);
});

test("digests are stable, keyed, and domain-separated", async () => {
    const a = createHasher("secret-one-that-is-long-enough-for-the-check");
    const b = createHasher("secret-two-that-is-long-enough-for-the-check");

    const first = await a("code", "value");
    assert.equal(first, await a("code", "value"), "same input must give the same digest");
    assert.notEqual(first, await b("code", "value"), "a different key must give a different digest");
    assert.notEqual(first, await a("token", "value"), "domains must not collide");
    assert.notEqual(first, await a("binding", "value"), "domains must not collide");
    assert.match(first, /^[0-9a-f]{64}$/, "expected a hex SHA-256 digest");
});

test("timingSafeEqual compares correctly", () => {
    assert.ok(timingSafeEqual("abc123", "abc123"));
    assert.ok(!timingSafeEqual("abc123", "abc124"));
    assert.ok(!timingSafeEqual("abc", "abcd"));
    assert.ok(!timingSafeEqual("", "a"));
    assert.ok(timingSafeEqual("", ""));
});
