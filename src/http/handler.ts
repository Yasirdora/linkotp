/**
 * Framework-agnostic HTTP adapter.
 *
 * Produces one `(Request) => Promise<Response>` function built on the Fetch
 * API, which every current JavaScript server runtime speaks natively: Next.js
 * route handlers, SvelteKit endpoints, Remix, Astro, Hono, Elysia, Nitro,
 * Deno.serve, Bun.serve, and Cloudflare Workers all accept it directly.
 * Express and other Node-stream frameworks need a small shim; see the README.
 *
 * Mounting is your call. The handler matches on `URL.pathname`, so it works
 * both as a catch-all and as individual routes.
 */

import type { LinkOtp } from "../core.ts";
import { LinkOtpError } from "../errors.ts";
import type { VerifiedIdentity } from "../types.ts";
import { createNonce, renderInterstitial, securityHeaders } from "./interstitial.ts";

/** What the application returns once an identity is proven. */
export interface VerifiedResponse {
    /** Headers to merge into the response, typically a session `Set-Cookie`. */
    readonly headers?: Readonly<Record<string, string>> | readonly (readonly [string, string])[];
    /** Where to send the browser after a link verification. */
    readonly redirectTo?: string;
}

export interface HandlerOptions {
    /** Mount point for the JSON endpoints. @default "/api/auth" */
    readonly basePath?: string;

    /**
     * Called once an address is proven. This is where you create a session.
     *
     * linkotp does not mint sessions, so whatever you return here is what
     * actually logs the user in. Set your own cookie, with your own flags,
     * through your own session library.
     */
    onVerified(identity: VerifiedIdentity, request: Request): Promise<VerifiedResponse>;

    /**
     * Runs before `start`. Throw to reject. This is where a CAPTCHA check, an
     * IP reputation lookup, or a gateway rate limiter belongs.
     */
    guard?(request: Request): Promise<void> | void;

    /** Derives the rate-limit key, conventionally the client IP. */
    clientKey?(request: Request): string | undefined;

    /** Where to send the browser when a link fails. Receives the error code. */
    failureRedirect?(error: LinkOtpError): string;

    /** Default post-sign-in destination for the link flow. @default "/" */
    successRedirect?: string;

    /** Product name shown on the confirmation page. @default "your account" */
    product?: string;

    /**
     * Whether the confirmation page submits itself. @default "auto"
     * @see renderInterstitial for the trade-off.
     */
    confirmation?: "auto" | "manual";

    /** Name of the device-binding cookie. @default "linkotp_binding" */
    bindingCookie?: string;

    /**
     * Marks cookies `Secure`. Defaults to true whenever the configured
     * baseUrl is https, which is every deployment except local development.
     */
    secureCookies?: boolean;
}

const JSON_HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
} as const;

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: { ...JSON_HEADERS, ...extra },
    });
}

function errorResponse(error: unknown): Response {
    if (LinkOtpError.is(error)) {
        const headers: Record<string, string> = {};
        if (error.retryAfter !== undefined) headers["Retry-After"] = String(error.retryAfter);
        return json(error.toJSON(), error.status, headers);
    }
    // An unexpected throw is a bug, not a user error. Never echo it outward.
    return json({ error: "internal_error", message: "Something went wrong." }, 500);
}

/** Reads one cookie without pulling in a parser. */
function readCookie(request: Request, name: string): string | undefined {
    const header = request.headers.get("cookie");
    if (!header) return undefined;
    for (const part of header.split(";")) {
        const eq = part.indexOf("=");
        if (eq === -1) continue;
        if (part.slice(0, eq).trim() === name) {
            return decodeURIComponent(part.slice(eq + 1).trim());
        }
    }
    return undefined;
}

/**
 * Rejects cross-site state-changing requests.
 *
 * The threat is login CSRF: an attacker submits *their* code or token from
 * the victim's browser, silently signing the victim into the attacker's
 * account, so that subsequent activity accrues to an account the attacker
 * controls. Checking that a state-changing POST originated from our own
 * origin closes it. `Sec-Fetch-Site` is authoritative where present; `Origin`
 * is the fallback for older clients.
 */
function isSameOrigin(request: Request, expectedOrigin: string): boolean {
    const fetchSite = request.headers.get("sec-fetch-site");
    if (fetchSite) return fetchSite === "same-origin" || fetchSite === "none";

    const origin = request.headers.get("origin");
    if (origin) return origin === expectedOrigin;

    // Neither header present. Old clients and some server-to-server callers
    // land here; the individual credential still has to be correct.
    return true;
}

async function readBody(request: Request): Promise<Record<string, unknown>> {
    const type = request.headers.get("content-type") ?? "";

    if (type.includes("application/json")) {
        try {
            const parsed: unknown = await request.json();
            return typeof parsed === "object" && parsed !== null
                ? (parsed as Record<string, unknown>)
                : {};
        } catch {
            return {};
        }
    }

    if (
        type.includes("application/x-www-form-urlencoded") ||
        type.includes("multipart/form-data")
    ) {
        try {
            return Object.fromEntries(await request.formData());
        } catch {
            return {};
        }
    }

    return {};
}

function mergeHeaders(
    into: Headers,
    from: VerifiedResponse["headers"],
): void {
    if (!from) return;
    const entries = Array.isArray(from)
        ? (from as readonly (readonly [string, string])[])
        : Object.entries(from as Record<string, string>);
    for (const [key, value] of entries) {
        // append, not set: a response may legitimately carry several
        // Set-Cookie headers, and set would collapse them into one.
        into.append(key, value);
    }
}

/**
 * Restricts a redirect to a same-origin path.
 *
 * An unvalidated `redirectTo` is an open redirect, which turns a trusted
 * sign-in domain into a springboard for phishing. Anything that is not a
 * single-slash-prefixed path is discarded rather than corrected, since
 * "correcting" attacker input tends to produce a second bypass.
 */
export function sanitizeRedirect(raw: unknown, fallback: string): string {
    if (typeof raw !== "string" || raw.length === 0) return fallback;
    if (!raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/\\")) return fallback;
    return raw;
}

export function createHandler(auth: LinkOtp, options: HandlerOptions) {
    const basePath = (options.basePath ?? "/api/auth").replace(/\/+$/, "");
    const verifyPath = auth.config.verifyPath;
    const product = options.product ?? "your account";
    const confirmation = options.confirmation ?? "auto";
    const bindingCookie = options.bindingCookie ?? "linkotp_binding";
    const successRedirect = options.successRedirect ?? "/";
    const secure = options.secureCookies ?? auth.config.baseUrl.startsWith("https:");

    const startPath = `${basePath}/start`;
    const verifyCodePath = `${basePath}/verify`;

    const failureRedirect =
        options.failureRedirect ?? ((error: LinkOtpError) => `/login?error=${error.code}`);

    function bindingCookieHeader(value: string): string {
        return [
            `${bindingCookie}=${encodeURIComponent(value)}`,
            "Path=/",
            "HttpOnly",
            // Lax, not Strict: the link arrives as a top-level cross-site
            // navigation from the mail client, and Strict would withhold the
            // cookie exactly then, breaking every bound sign-in.
            "SameSite=Lax",
            `Max-Age=${Math.ceil(auth.config.ttlMs / 1000)}`,
            ...(secure ? ["Secure"] : []),
        ].join("; ");
    }

    async function handleStart(request: Request): Promise<Response> {
        if (!isSameOrigin(request, auth.config.baseUrl)) {
            return json({ error: "invalid_challenge", message: "Cross-origin request." }, 403);
        }

        await options.guard?.(request);

        const body = await readBody(request);
        const rateLimitKey = options.clientKey?.(request);
        const binding = auth.config.bindingEnabled
            ? (readCookie(request, bindingCookie) ?? createNonce())
            : undefined;

        const result = await auth.start({
            email: String(body.email ?? ""),
            ...(typeof body.purpose === "string" ? { purpose: body.purpose } : {}),
            ...(binding !== undefined ? { binding } : {}),
            ...(rateLimitKey !== undefined ? { rateLimitKey } : {}),
            ...(request.signal ? { signal: request.signal } : {}),
        });

        const headers: Record<string, string> = {};
        if (binding !== undefined) headers["Set-Cookie"] = bindingCookieHeader(binding);

        return json(result, 200, headers);
    }

    async function handleVerifyCode(request: Request): Promise<Response> {
        if (!isSameOrigin(request, auth.config.baseUrl)) {
            return json({ error: "invalid_code", message: "Cross-origin request." }, 403);
        }

        const body = await readBody(request);
        const rateLimitKey = options.clientKey?.(request);
        const binding = readCookie(request, bindingCookie);

        const identity = await auth.verifyCode({
            email: String(body.email ?? ""),
            code: String(body.code ?? ""),
            ...(typeof body.purpose === "string" ? { purpose: body.purpose } : {}),
            ...(binding !== undefined ? { binding } : {}),
            ...(rateLimitKey !== undefined ? { rateLimitKey } : {}),
        });

        const outcome = await options.onVerified(identity, request);
        const headers = new Headers(JSON_HEADERS);
        mergeHeaders(headers, outcome.headers);
        headers.append("Set-Cookie", `${bindingCookie}=; Path=/; Max-Age=0`);

        return new Response(
            JSON.stringify({
                ok: true,
                email: identity.email,
                redirectTo: sanitizeRedirect(outcome.redirectTo, successRedirect),
            }),
            { status: 200, headers },
        );
    }

    /**
     * Renders the confirmation page. Reads nothing, writes nothing, consumes
     * nothing, so a link scanner that fetches it changes no state.
     */
    function handleVerifyPage(url: URL): Response {
        const token = url.searchParams.get("token") ?? "";
        const nonce = createNonce();

        return new Response(
            renderInterstitial({
                token,
                action: verifyPath,
                product,
                mode: confirmation,
                nonce,
            }),
            { status: 200, headers: securityHeaders(nonce) },
        );
    }

    async function handleVerifyToken(request: Request): Promise<Response> {
        if (!isSameOrigin(request, auth.config.baseUrl)) {
            return Response.redirect(
                new URL(
                    failureRedirect(new LinkOtpError("invalid_token", "cross-origin")),
                    auth.config.baseUrl,
                ),
                303,
            );
        }

        const body = await readBody(request);
        const rateLimitKey = options.clientKey?.(request);
        const binding = readCookie(request, bindingCookie);

        let identity: VerifiedIdentity;
        try {
            identity = await auth.verifyToken({
                token: String(body.token ?? ""),
                ...(binding !== undefined ? { binding } : {}),
                ...(rateLimitKey !== undefined ? { rateLimitKey } : {}),
            });
        } catch (error) {
            if (!LinkOtpError.is(error)) throw error;
            const headers = new Headers({
                Location: new URL(failureRedirect(error), auth.config.baseUrl).toString(),
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
            });
            return new Response(null, { status: 303, headers });
        }

        const outcome = await options.onVerified(identity, request);
        const headers = new Headers({
            Location: new URL(
                sanitizeRedirect(outcome.redirectTo, successRedirect),
                auth.config.baseUrl,
            ).toString(),
            // The inbound URL carried the token. Without this, the token
            // reaches the destination page as a Referer, and from there any
            // third-party script on it.
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
        });
        mergeHeaders(headers, outcome.headers);
        headers.append("Set-Cookie", `${bindingCookie}=; Path=/; Max-Age=0`);

        // 303 forces the follow-up to be a GET. A 302 after a POST leaves the
        // method up to the client, and some will re-POST to the destination.
        return new Response(null, { status: 303, headers });
    }

    return async function handle(request: Request): Promise<Response> {
        const url = new URL(request.url);
        const { pathname } = url;
        const method = request.method.toUpperCase();

        try {
            if (pathname === startPath && method === "POST") {
                return await handleStart(request);
            }
            if (pathname === verifyCodePath && method === "POST") {
                return await handleVerifyCode(request);
            }
            if (pathname === verifyPath) {
                if (method === "GET" || method === "HEAD") return handleVerifyPage(url);
                if (method === "POST") return await handleVerifyToken(request);
            }
            return json({ error: "not_found", message: "No such route." }, 404);
        } catch (error) {
            return errorResponse(error);
        }
    };
}
