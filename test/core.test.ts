import { test } from "node:test";
import assert from "node:assert/strict";

import { createOtpLink } from "../src/core.ts";
import { createMemoryStore } from "../src/stores/memory.ts";
import { createMemoryRateLimiter } from "../src/ratelimit.ts";
import { expectError, harness, BASE_URL, NOW, SECRET } from "./helpers.ts";

test("start sends exactly one message carrying both the code and the link", async () => {
    const h = harness();
    const result = await h.auth.start({ email: "Person@Example.com" });

    assert.equal(h.sent.length, 1);
    const message = h.sent[0]!;
    assert.equal(message.to, "person@example.com", "the recipient must be normalized");
    assert.equal(result.sent, true);
    assert.equal(result.codeLength, 6);
    assert.equal(result.expiresAt, NOW + 900_000);

    const code = h.lastCode();
    const token = h.lastToken();
    assert.equal(code.length, 6);
    assert.equal(token.length, 48);

    // Both arms in one message is the entire premise.
    assert.ok(message.text.includes(code), "the plain-text part must carry the code");
    assert.ok(message.html.includes(code), "the HTML part must carry the code");
    assert.ok(message.html.includes(`${BASE_URL}/auth/verify?token=${token}`));
    assert.ok(message.text.length > 0, "a plain-text alternative is required");
});

test("the link token is independent of the code", async () => {
    const h = harness();
    await h.auth.start({ email: "person@example.com" });
    // The defect this package exists to fix: the link must not carry the code.
    assert.ok(!h.lastToken().includes(h.lastCode()));
    assert.ok(!h.sent[0]!.html.includes(`token=${h.lastCode()}`));
});

test("verifyCode accepts the issued code and returns the identity", async () => {
    const h = harness();
    await h.auth.start({ email: "person@example.com", metadata: { plan: "pro" } });

    const identity = await h.auth.verifyCode({
        email: "person@example.com",
        code: h.lastCode(),
    });

    assert.equal(identity.email, "person@example.com");
    assert.equal(identity.via, "code");
    assert.equal(identity.purpose, "sign-in");
    assert.deepEqual(identity.metadata, { plan: "pro" });
    assert.equal(identity.verifiedAt, NOW);
});

test("verifyCode tolerates spacing, case, and separators", async () => {
    const h = harness();
    await h.auth.start({ email: "person@example.com" });
    const code = h.lastCode();
    const typed = `${code.slice(0, 3).toLowerCase()} - ${code.slice(3).toLowerCase()}`;

    const identity = await h.auth.verifyCode({ email: "person@example.com", code: typed });
    assert.equal(identity.email, "person@example.com");
});

test("verifyToken accepts the issued token", async () => {
    const h = harness();
    await h.auth.start({ email: "person@example.com" });

    const identity = await h.auth.verifyToken({ token: h.lastToken() });
    assert.equal(identity.email, "person@example.com");
    assert.equal(identity.via, "link");
});

test("a code can be redeemed only once", async () => {
    const h = harness();
    await h.auth.start({ email: "person@example.com" });
    const code = h.lastCode();

    await h.auth.verifyCode({ email: "person@example.com", code });
    await expectError(
        () => h.auth.verifyCode({ email: "person@example.com", code }),
        "invalid_code",
    );
});

test("a token can be redeemed only once", async () => {
    const h = harness();
    await h.auth.start({ email: "person@example.com" });
    const token = h.lastToken();

    await h.auth.verifyToken({ token });
    await expectError(() => h.auth.verifyToken({ token }), "invalid_token");
});

test("redeeming either arm retires the other", async () => {
    // Both secrets belong to one challenge, so signing in with the code must
    // also kill the link still sitting in the inbox.
    const h = harness();
    await h.auth.start({ email: "person@example.com" });
    const token = h.lastToken();

    await h.auth.verifyCode({ email: "person@example.com", code: h.lastCode() });
    await expectError(() => h.auth.verifyToken({ token }), "invalid_token");
});

test("concurrent token redemptions elect exactly one winner", async () => {
    const h = harness();
    await h.auth.start({ email: "person@example.com" });
    const token = h.lastToken();

    const outcomes = await Promise.allSettled(
        Array.from({ length: 32 }, () => h.auth.verifyToken({ token })),
    );
    const wins = outcomes.filter((o) => o.status === "fulfilled").length;
    assert.equal(wins, 1, `${wins} of 32 concurrent redemptions succeeded; expected exactly 1`);
});

test("an expired challenge is rejected on both arms", async () => {
    const h = harness();
    await h.auth.start({ email: "person@example.com" });
    const code = h.lastCode();
    const token = h.lastToken();

    h.advance(900_001);

    await expectError(() => h.auth.verifyToken({ token }), "invalid_token");
    // Expiry is absence, not exhaustion: there is nothing left to attempt.
    await expectError(
        () => h.auth.verifyCode({ email: "person@example.com", code }),
        "invalid_code",
    );
});

test("a wrong code burns an attempt and reports the remainder", async () => {
    const h = harness({ maxAttempts: 3 });
    await h.auth.start({ email: "person@example.com" });

    try {
        await h.auth.verifyCode({ email: "person@example.com", code: "ZZZZZZ" });
        assert.fail("expected a rejection");
    } catch (error) {
        assert.equal((error as { code: string }).code, "invalid_code");
        assert.equal((error as { remainingAttempts: number }).remainingAttempts, 2);
    }
});

test("exhausting the attempt budget retires the challenge permanently", async () => {
    const h = harness({ maxAttempts: 3 });
    await h.auth.start({ email: "person@example.com" });
    const realCode = h.lastCode();

    const wrong = () => h.auth.verifyCode({ email: "person@example.com", code: "ZZZZZZ" });

    await expectError(wrong, "invalid_code");
    await expectError(wrong, "invalid_code");
    // The submission that spends the last attempt says so, rather than
    // reporting a wrong code and leaving the user to guess why retrying never
    // works.
    await expectError(wrong, "too_many_attempts");

    // Even the correct code must now fail: the budget is gone.
    await expectError(
        () => h.auth.verifyCode({ email: "person@example.com", code: realCode }),
        "too_many_attempts",
    );
});

test("a malformed code still burns an attempt", async () => {
    // Short-circuiting on length would hand an attacker free probes against
    // the attempt counter.
    const h = harness({ maxAttempts: 2 });
    await h.auth.start({ email: "person@example.com" });
    const realCode = h.lastCode();

    await expectError(
        () => h.auth.verifyCode({ email: "person@example.com", code: "X" }),
        "invalid_code",
    );
    await expectError(
        () => h.auth.verifyCode({ email: "person@example.com", code: "" }),
        "too_many_attempts",
    );
    await expectError(
        () => h.auth.verifyCode({ email: "person@example.com", code: realCode }),
        "too_many_attempts",
    );
});

test("a code issued to one address cannot be redeemed by another", async () => {
    const h = harness();
    await h.auth.start({ email: "victim@example.com" });
    const victimCode = h.lastCode();
    await h.auth.start({ email: "attacker@example.com" });

    await expectError(
        () => h.auth.verifyCode({ email: "attacker@example.com", code: victimCode }),
        "invalid_code",
    );
});

test("a failed delivery rolls the challenge back", async () => {
    const store = createMemoryStore();
    const auth = createOtpLink({
        secret: SECRET,
        baseUrl: BASE_URL,
        store,
        minimumStartDurationMs: 0,
        mailer: async () => {
            throw new Error("smtp exploded");
        },
    });

    await expectError(() => auth.start({ email: "person@example.com" }), "delivery_failed");
    assert.equal(store.size(), 0, "a live secret was left behind after a failed send");
});

test("shouldSend suppresses delivery without changing the observable result", async () => {
    const allowed = harness({ shouldSend: () => true });
    const blocked = harness({ shouldSend: () => false });

    const a = await allowed.auth.start({ email: "person@example.com" });
    const b = await blocked.auth.start({ email: "person@example.com" });

    // This is what closes sign-ups without leaking which addresses exist.
    assert.deepEqual(a, b, "the suppressed result must be indistinguishable");
    assert.equal(allowed.sent.length, 1);
    assert.equal(blocked.sent.length, 0);
});

test("shouldSend receives the normalized address and context", async () => {
    const seen: Array<{ email: string; purpose: string }> = [];
    const h = harness({
        shouldSend: (email, context) => {
            seen.push({ email, purpose: context.purpose });
            return true;
        },
    });

    await h.auth.start({ email: "  Person@EXAMPLE.com ", purpose: "sign-up" });
    assert.deepEqual(seen, [{ email: "person@example.com", purpose: "sign-up" }]);
});

test("the per-address send cap holds", async () => {
    const h = harness({ maxSendsPerAddress: { count: 2, windowSeconds: 900 } });

    await h.auth.start({ email: "person@example.com" });
    await h.auth.start({ email: "person@example.com" });
    await expectError(() => h.auth.start({ email: "person@example.com" }), "rate_limited");

    // A different address is unaffected.
    await h.auth.start({ email: "other@example.com" });
    assert.equal(h.sent.length, 3);
});

test("the send cap counts redeemed challenges too", async () => {
    const h = harness({ maxSendsPerAddress: { count: 1, windowSeconds: 900 } });
    await h.auth.start({ email: "person@example.com" });
    await h.auth.verifyCode({ email: "person@example.com", code: h.lastCode() });

    // Otherwise redeeming a code resets the quota and the cap means nothing.
    await expectError(() => h.auth.start({ email: "person@example.com" }), "rate_limited");
});

test("an external rate limiter is consulted and its retryAfter surfaces", async () => {
    const h = harness({
        rateLimiter: createMemoryRateLimiter({ limit: 2, windowSeconds: 60 }),
    });

    await h.auth.start({ email: "a@example.com", rateLimitKey: "203.0.113.7" });
    await h.auth.start({ email: "b@example.com", rateLimitKey: "203.0.113.7" });

    try {
        await h.auth.start({ email: "c@example.com", rateLimitKey: "203.0.113.7" });
        assert.fail("expected the limiter to reject the third request");
    } catch (error) {
        assert.equal((error as { code: string }).code, "rate_limited");
        assert.ok((error as { retryAfter: number }).retryAfter > 0);
    }

    // A different key is independent.
    await h.auth.start({ email: "d@example.com", rateLimitKey: "198.51.100.4" });
});

test("binding admits the issuing device and rejects any other", async () => {
    const h = harness({ binding: { enabled: true } });
    await h.auth.start({ email: "person@example.com", binding: "browser-a" });
    const token = h.lastToken();

    await expectError(
        () => h.auth.verifyToken({ token, binding: "browser-b" }),
        "binding_mismatch",
    );
    // A mismatch burns the challenge: the presenter was not the initiator.
    await expectError(() => h.auth.verifyToken({ token, binding: "browser-a" }), "invalid_token");
});

test("binding accepts the matching device", async () => {
    const h = harness({ binding: { enabled: true } });
    await h.auth.start({ email: "person@example.com", binding: "browser-a" });

    const identity = await h.auth.verifyToken({ token: h.lastToken(), binding: "browser-a" });
    assert.equal(identity.email, "person@example.com");
});

test("binding rejects a redemption presenting no binding at all", async () => {
    const h = harness({ binding: { enabled: true } });
    await h.auth.start({ email: "person@example.com", binding: "browser-a" });

    await expectError(() => h.auth.verifyToken({ token: h.lastToken() }), "binding_mismatch");
});

test("binding is ignored when disabled", async () => {
    const h = harness();
    await h.auth.start({ email: "person@example.com", binding: "browser-a" });
    const identity = await h.auth.verifyToken({ token: h.lastToken(), binding: "anything" });
    assert.equal(identity.email, "person@example.com");
});

test("a challenge issued under a rotated-out secret still verifies", async () => {
    const store = createMemoryStore();
    const sent: string[] = [];
    const old = "previous-secret-that-is-also-32-characters-long";

    const before = createOtpLink({
        secret: old,
        baseUrl: BASE_URL,
        store,
        minimumStartDurationMs: 0,
        mailer: async (message) => {
            sent.push(message.text);
        },
    });
    await before.start({ email: "person@example.com" });
    const token = /token=([A-Za-z0-9]+)/.exec(sent[0]!)![1]!;

    // Same store, new secret, old one retained for the rotation window.
    const after = createOtpLink({
        secret: SECRET,
        baseUrl: BASE_URL,
        store,
        minimumStartDurationMs: 0,
        rotation: { previous: [old] },
        mailer: async () => {},
    });

    const identity = await after.verifyToken({ token });
    assert.equal(identity.email, "person@example.com");
});

test("a challenge is unreadable once its secret leaves the rotation list", async () => {
    const store = createMemoryStore();
    const sent: string[] = [];
    const old = "previous-secret-that-is-also-32-characters-long";

    const before = createOtpLink({
        secret: old,
        baseUrl: BASE_URL,
        store,
        minimumStartDurationMs: 0,
        mailer: async (message) => {
            sent.push(message.text);
        },
    });
    await before.start({ email: "person@example.com" });
    const token = /token=([A-Za-z0-9]+)/.exec(sent[0]!)![1]!;

    const after = createOtpLink({
        secret: SECRET,
        baseUrl: BASE_URL,
        store,
        minimumStartDurationMs: 0,
        mailer: async () => {},
    });

    await expectError(() => after.verifyToken({ token }), "invalid_token");
});

test("start pads fast paths up to the configured floor", async () => {
    const h = harness({ minimumStartDurationMs: 120, shouldSend: () => false });

    const began = Date.now();
    await h.auth.start({ email: "person@example.com" });
    const elapsed = Date.now() - began;

    assert.ok(elapsed >= 110, `expected the floor to hold, took ${elapsed}ms`);
});

test("start pads even when validation rejects the address", async () => {
    // Otherwise a malformed address returns instantly and a real one does not,
    // which is a timing oracle on the validator itself.
    const h = harness({ minimumStartDurationMs: 120 });

    const began = Date.now();
    await expectError(() => h.auth.start({ email: "nonsense" }), "invalid_email");
    const elapsed = Date.now() - began;

    assert.ok(elapsed >= 110, `expected the floor to hold, took ${elapsed}ms`);
});

test("sweep removes only expired challenges", async () => {
    const h = harness();
    await h.auth.start({ email: "old@example.com" });
    h.advance(900_001);
    await h.auth.start({ email: "new@example.com" });
    const liveToken = h.lastToken();

    const removed = await h.auth.sweep();
    assert.equal(removed, 1);
    assert.equal((await h.auth.verifyToken({ token: liveToken })).email, "new@example.com");
});

test("an unknown token is rejected without disclosing why", async () => {
    const h = harness();
    await expectError(() => h.auth.verifyToken({ token: "not-a-real-token" }), "invalid_token");
    await expectError(() => h.auth.verifyToken({ token: "" }), "invalid_token");
});

test("purposes are isolated from one another", async () => {
    const h = harness();
    await h.auth.start({ email: "person@example.com", purpose: "sign-in" });
    const code = h.lastCode();

    await expectError(
        () => h.auth.verifyCode({ email: "person@example.com", code, purpose: "verify-email" }),
        "invalid_code",
    );
    const identity = await h.auth.verifyCode({
        email: "person@example.com",
        code,
        purpose: "sign-in",
    });
    assert.equal(identity.purpose, "sign-in");
});
