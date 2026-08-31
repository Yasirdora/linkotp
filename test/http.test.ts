import { test } from "node:test";
import assert from "node:assert/strict";

import { createHandler, sanitizeRedirect } from "../src/http/handler.ts";
import { harness, BASE_URL } from "./helpers.ts";
import type { VerifiedIdentity } from "../src/types.ts";

function setup(overrides: Record<string, unknown> = {}) {
    const h = harness();
    const verified: VerifiedIdentity[] = [];

    const handler = createHandler(h.auth, {
        onVerified: async (identity) => {
            verified.push(identity);
            return { headers: { "Set-Cookie": "session=abc123; Path=/; HttpOnly" } };
        },
        ...overrides,
    });

    return { ...h, handler, verified };
}

const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
    new Request(`${BASE_URL}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", ...headers },
        body: JSON.stringify(body),
    });

const postForm = (path: string, fields: Record<string, string>, headers: Record<string, string> = {}) =>
    new Request(`${BASE_URL}${path}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Sec-Fetch-Site": "same-origin",
            ...headers,
        },
        body: new URLSearchParams(fields).toString(),
    });

test("GET on the verify route does not consume the token", async () => {
    // This is the defect the whole GET/POST split exists to prevent. Mail
    // security appliances fetch every link in inbound mail; if that fetch
    // consumed the token, the recipient would find their link already spent.
    const s = setup();
    await s.auth.start({ email: "person@example.com" });
    const token = s.lastToken();

    // Simulate Defender, Proofpoint, Mimecast, and a link preview all firing.
    for (let i = 0; i < 4; i++) {
        const response = await s.handler(
            new Request(`${BASE_URL}/auth/verify?token=${token}`, { method: "GET" }),
        );
        assert.equal(response.status, 200);
        assert.ok(!response.headers.get("set-cookie"), "a GET must not mint a session");
    }

    assert.equal(s.verified.length, 0, "onVerified fired during a passive fetch");

    // The user's own click must still work after all of that.
    const response = await s.handler(postForm("/auth/verify", { token }));
    assert.equal(response.status, 303);
    assert.equal(s.verified.length, 1);
    assert.equal(s.verified[0]!.email, "person@example.com");
});

test("the confirmation page carries the token in a form, not a link", async () => {
    const s = setup();
    await s.auth.start({ email: "person@example.com" });
    const token = s.lastToken();

    const response = await s.handler(
        new Request(`${BASE_URL}/auth/verify?token=${token}`, { method: "GET" }),
    );
    const html = await response.text();

    assert.match(html, /<form[^>]+method="POST"/i);
    assert.ok(html.includes(`value="${token}"`), "the form must replay the token");
    assert.match(html, /action="\/auth\/verify"/);
});

test("the confirmation page sets the headers that keep a token private", async () => {
    const s = setup();
    const response = await s.handler(
        new Request(`${BASE_URL}/auth/verify?token=abc`, { method: "GET" }),
    );

    const headers = response.headers;
    assert.match(headers.get("cache-control") ?? "", /no-store/);
    assert.equal(headers.get("referrer-policy"), "no-referrer");
    assert.match(headers.get("x-robots-tag") ?? "", /noindex/);
    assert.equal(headers.get("x-frame-options"), "DENY");
    assert.equal(headers.get("x-content-type-options"), "nosniff");

    const csp = headers.get("content-security-policy") ?? "";
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /form-action 'self'/);
    assert.match(csp, /script-src 'nonce-[A-Za-z0-9]{22}'/);
    assert.ok(!csp.includes("unsafe-inline'; script"), "scripts must not be blanket-allowed");
});

test("each confirmation page gets a fresh nonce", async () => {
    const s = setup();
    const nonces = new Set<string>();

    for (let i = 0; i < 5; i++) {
        const response = await s.handler(
            new Request(`${BASE_URL}/auth/verify?token=abc`, { method: "GET" }),
        );
        const csp = response.headers.get("content-security-policy") ?? "";
        const html = await response.text();
        const nonce = /'nonce-([A-Za-z0-9]+)'/.exec(csp)![1]!;
        assert.ok(html.includes(`nonce="${nonce}"`), "the page must carry the header's nonce");
        nonces.add(nonce);
    }

    // A reused nonce is worth no more than 'unsafe-inline'.
    assert.equal(nonces.size, 5);
});

test("a successful link redemption redirects with the session attached", async () => {
    const s = setup({
        onVerified: async () => ({
            headers: [
                ["Set-Cookie", "session=abc; Path=/; HttpOnly"],
                ["Set-Cookie", "theme=dark; Path=/"],
            ],
            redirectTo: "/dashboard",
        }),
    });
    await s.auth.start({ email: "person@example.com" });

    const response = await s.handler(postForm("/auth/verify", { token: s.lastToken() }));

    assert.equal(response.status, 303, "303 forces the follow-up request to be a GET");
    assert.equal(response.headers.get("location"), `${BASE_URL}/dashboard`);
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");

    // Several Set-Cookie headers must survive as separate headers.
    const cookies = response.headers.getSetCookie();
    assert.ok(cookies.some((c) => c.startsWith("session=abc")));
    assert.ok(cookies.some((c) => c.startsWith("theme=dark")));
});

test("a failed link redemption redirects instead of leaking a reason", async () => {
    const s = setup();
    const response = await s.handler(postForm("/auth/verify", { token: "not-a-real-token" }));

    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), `${BASE_URL}/login?error=invalid_token`);
    assert.equal(s.verified.length, 0);
});

test("cross-origin submissions are refused", async () => {
    // Login CSRF: an attacker submitting their own credential from the
    // victim's browser, silently signing the victim into the attacker account.
    const s = setup();
    await s.auth.start({ email: "person@example.com" });

    const evil = { "Sec-Fetch-Site": "cross-site" };
    assert.equal((await s.handler(post("/api/auth/start", { email: "x@y.com" }, evil))).status, 403);
    assert.equal(
        (await s.handler(post("/api/auth/verify", { email: "x@y.com", code: "ABC123" }, evil))).status,
        403,
    );

    const link = await s.handler(postForm("/auth/verify", { token: s.lastToken() }, evil));
    assert.equal(link.status, 303);
    assert.match(link.headers.get("location") ?? "", /error=invalid_token/);
    assert.equal(s.verified.length, 0);
});

test("an Origin header is honoured when Sec-Fetch-Site is absent", async () => {
    const s = setup();
    const good = await s.handler(
        new Request(`${BASE_URL}/api/auth/start`, {
            method: "POST",
            headers: { "Content-Type": "application/json", Origin: BASE_URL },
            body: JSON.stringify({ email: "person@example.com" }),
        }),
    );
    assert.equal(good.status, 200);

    const bad = await s.handler(
        new Request(`${BASE_URL}/api/auth/start`, {
            method: "POST",
            headers: { "Content-Type": "application/json", Origin: "https://evil.test" },
            body: JSON.stringify({ email: "person@example.com" }),
        }),
    );
    assert.equal(bad.status, 403);
});

test("the start endpoint issues a challenge and reports the shape of it", async () => {
    const s = setup();
    const response = await s.handler(post("/api/auth/start", { email: "Person@Example.com" }));

    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await response.json(), {
        sent: true,
        expiresAt: s.auth.config.ttlMs + 1_700_000_000_000,
        codeLength: 6,
    });
    assert.equal(s.sent.length, 1);
});

test("the start endpoint reports a bad address without sending", async () => {
    const s = setup();
    const response = await s.handler(post("/api/auth/start", { email: "not-an-address" }));

    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, "invalid_email");
    assert.equal(s.sent.length, 0);
});

test("the code endpoint verifies and hands back the session", async () => {
    const s = setup();
    await s.auth.start({ email: "person@example.com" });

    const response = await s.handler(
        post("/api/auth/verify", { email: "person@example.com", code: s.lastCode() }),
    );

    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.ok, true);
    assert.equal(body.email, "person@example.com");
    assert.ok(response.headers.getSetCookie().some((c) => c.startsWith("session=abc123")));
    assert.equal(s.verified[0]!.via, "code");
});

test("a wrong code returns a 400 carrying the remaining attempts", async () => {
    const s = setup();
    await s.auth.start({ email: "person@example.com" });

    const response = await s.handler(
        post("/api/auth/verify", { email: "person@example.com", code: "ZZZZZZ" }),
    );
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, "invalid_code");
});

test("a rate-limited request answers 429 with Retry-After", async () => {
    const s = setup();
    for (let i = 0; i < 5; i++) {
        await s.handler(post("/api/auth/start", { email: "person@example.com" }));
    }
    const response = await s.handler(post("/api/auth/start", { email: "person@example.com" }));

    assert.equal(response.status, 429);
    assert.ok(Number(response.headers.get("retry-after")) > 0);
});

test("the guard hook can reject before anything is issued", async () => {
    const s = setup({
        guard: () => {
            throw new Error("captcha failed");
        },
    });

    const response = await s.handler(post("/api/auth/start", { email: "person@example.com" }));
    assert.equal(response.status, 500);
    // An unexpected throw must never echo its message outward.
    assert.equal((await response.json()).message, "Something went wrong.");
    assert.equal(s.sent.length, 0);
});

test("unknown routes are 404", async () => {
    const s = setup();
    const response = await s.handler(new Request(`${BASE_URL}/nope`, { method: "GET" }));
    assert.equal(response.status, 404);
});

test("sanitizeRedirect blocks every open-redirect shape", async () => {
    for (const evil of [
        "https://evil.test",
        "//evil.test",
        "/\\evil.test",
        "http://evil.test/path",
        "javascript:alert(1)",
        "",
        null,
        undefined,
        42,
    ]) {
        assert.equal(sanitizeRedirect(evil, "/safe"), "/safe", `should reject ${String(evil)}`);
    }

    assert.equal(sanitizeRedirect("/dashboard", "/safe"), "/dashboard");
    assert.equal(sanitizeRedirect("/a/b?c=d#e", "/safe"), "/a/b?c=d#e");
});

test("an application-supplied redirect cannot leave the origin", async () => {
    const s = setup({ onVerified: async () => ({ redirectTo: "https://evil.test/steal" }) });
    await s.auth.start({ email: "person@example.com" });

    const response = await s.handler(postForm("/auth/verify", { token: s.lastToken() }));
    assert.equal(response.headers.get("location"), `${BASE_URL}/`);
});

test("device binding survives a full round trip through HTTP", async () => {
    const h = harness({ binding: { enabled: true } });
    const verified: VerifiedIdentity[] = [];
    const handler = createHandler(h.auth, {
        onVerified: async (identity) => {
            verified.push(identity);
            return {};
        },
    });

    const started = await handler(post("/api/auth/start", { email: "person@example.com" }));
    const cookie = started.headers.getSetCookie().find((c) => c.startsWith("linkotp_binding="))!;
    assert.ok(cookie, "start must set the binding cookie");
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Lax/);
    // Strict would withhold the cookie on the cross-site navigation from the
    // mail client, breaking every bound sign-in.
    assert.ok(!cookie.includes("SameSite=Strict"));
    assert.match(cookie, /Secure/);

    const value = cookie.split(";")[0]!;
    const token = h.lastToken();

    // Same browser: the cookie comes back, so the redemption succeeds.
    const ok = await handler(postForm("/auth/verify", { token }, { cookie: value }));
    assert.equal(ok.status, 303);
    assert.equal(verified.length, 1);
});

test("device binding rejects a redemption from a different browser", async () => {
    const h = harness({ binding: { enabled: true } });
    const verified: VerifiedIdentity[] = [];
    const handler = createHandler(h.auth, {
        onVerified: async (identity) => {
            verified.push(identity);
            return {};
        },
    });

    await handler(post("/api/auth/start", { email: "person@example.com" }));
    const token = h.lastToken();

    const response = await handler(
        postForm("/auth/verify", { token }, { cookie: "linkotp_binding=someone-elses" }),
    );
    assert.equal(response.status, 303);
    assert.match(response.headers.get("location") ?? "", /error=binding_mismatch/);
    assert.equal(verified.length, 0);
});

test("the manual confirmation mode does not auto-submit", async () => {
    const s = setup({ confirmation: "manual" });
    const response = await s.handler(
        new Request(`${BASE_URL}/auth/verify?token=abc`, { method: "GET" }),
    );
    const html = await response.text();

    assert.ok(!html.includes(".submit()"), "manual mode must wait for a real click");
    assert.match(html, /Confirm sign-in/);
});

test("the confirmation page escapes a hostile token", async () => {
    const s = setup();
    const token = '"><script>fetch("//evil.test")</script>';
    const response = await s.handler(
        new Request(`${BASE_URL}/auth/verify?token=${encodeURIComponent(token)}`, {
            method: "GET",
        }),
    );
    const html = await response.text();

    assert.ok(!html.includes("<script>fetch"), "the token was interpolated unescaped");
    assert.ok(html.includes("&quot;&gt;&lt;script&gt;"));
});
