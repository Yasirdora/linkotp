/**
 * The Better Auth plugin.
 *
 * Better Auth's own `magicLink` plugin redeems its token on `GET`, which is
 * why [discussion #6985](https://github.com/better-auth/better-auth/discussions/6985)
 * exists: corporate mail scanners fetch every link in inbound mail, burn the
 * single-use credential, and the user is told their brand-new link expired.
 * The workaround the community reaches for — raising `allowedAttempts` — does
 * not fix it. It converts a single-use credential into a multi-use one, which
 * is a downgrade dressed as a fix.
 *
 * This plugin does it the other way round. `GET /otplink/verify` renders a
 * confirmation page and touches nothing; only the `POST` that page submits
 * redeems the token. Automated fetchers issue `GET` and stop there, so the
 * credential survives the scan. And because every email also carries a typed
 * code on a *separate* secret, a user whose link is mangled entirely still
 * has a way in.
 *
 * Sessions stay Better Auth's: otplink verifies control of an address and
 * hands off to `internalAdapter` and `setSessionCookie` for everything after
 * that.
 */

import { APIError, createAuthEndpoint, getIp, originCheck } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";

import type { OtpLinkOptions } from "../config.ts";
import { createOtpLink, type OtpLink } from "../core.ts";
import { OtpLinkError, type OtpLinkErrorCode } from "../errors.ts";
import { createNonce, renderInterstitial, securityHeaders } from "../http/interstitial.ts";
import type { TokenStore, VerifiedIdentity } from "../types.ts";
import { otplinkSchema } from "./schema.ts";
import { createBetterAuthStore, DEFAULT_MODEL, type BetterAuthAdapterLike } from "./store.ts";
import { object, optional, record, string } from "./validate.ts";

/** Context shape `setSessionCookie` expects, derived rather than imported. */
type SessionContext = Parameters<typeof setSessionCookie>[0];

export interface OtplinkPluginOptions extends Omit<OtpLinkOptions, "store"> {
    /**
     * Model name for the challenge table. Must match {@link otplinkSchema}.
     * @default "otplinkChallenge"
     */
    readonly model?: string;

    /**
     * How the confirmation page behaves.
     *
     * "auto" submits on load, so a human sees a brief spinner. "manual"
     * requires a click, which additionally defeats the small minority of
     * scanners that execute JavaScript, at the cost of one interaction.
     *
     * @default "auto"
     */
    readonly interstitialMode?: "auto" | "manual";

    /**
     * Reject addresses with no existing account instead of creating one.
     *
     * Note this is observable: a caller learns whether an address has an
     * account from the verify response. Use otplink's own `shouldSend` to
     * suppress delivery silently at `start` time if enumeration matters.
     *
     * @default false
     */
    readonly disableSignUp?: boolean;

    /** Where to send the browser after a successful sign-in. @default "/" */
    readonly defaultCallbackURL?: string;

    /** Per-path throttle Better Auth applies in front of the endpoints. */
    readonly rateLimit?: { readonly window?: number; readonly max?: number };
}

export const OTPLINK_ERROR_CODES = {
    OTPLINK_INVALID_EMAIL: "Enter a valid email address.",
    OTPLINK_RATE_LIMITED: "Too many attempts. Please wait a moment and try again.",
    OTPLINK_INVALID_CODE: "That code is incorrect or has expired.",
    OTPLINK_TOO_MANY_ATTEMPTS: "Too many incorrect attempts. Request a new code.",
    OTPLINK_INVALID_TOKEN: "That link is no longer valid. Request a new one.",
    OTPLINK_BINDING_MISMATCH: "Open the link in the same browser you started from.",
    OTPLINK_DELIVERY_FAILED: "We couldn't send that email. Please try again.",
    OTPLINK_SIGNUP_DISABLED: "That address does not have an account.",
} as const;

/** Maps the protocol's error taxonomy onto Better Auth's HTTP errors. */
const STATUS: Record<
    OtpLinkErrorCode,
    "BAD_REQUEST" | "TOO_MANY_REQUESTS" | "BAD_GATEWAY" | "INTERNAL_SERVER_ERROR"
> = {
    invalid_email: "BAD_REQUEST",
    rate_limited: "TOO_MANY_REQUESTS",
    invalid_challenge: "BAD_REQUEST",
    invalid_code: "BAD_REQUEST",
    too_many_attempts: "TOO_MANY_REQUESTS",
    invalid_token: "BAD_REQUEST",
    binding_mismatch: "BAD_REQUEST",
    delivery_failed: "BAD_GATEWAY",
    configuration_error: "INTERNAL_SERVER_ERROR",
};

const CODE_NAMES: Record<OtpLinkErrorCode, string> = {
    invalid_email: "OTPLINK_INVALID_EMAIL",
    rate_limited: "OTPLINK_RATE_LIMITED",
    invalid_challenge: "OTPLINK_INVALID_TOKEN",
    invalid_code: "OTPLINK_INVALID_CODE",
    too_many_attempts: "OTPLINK_TOO_MANY_ATTEMPTS",
    invalid_token: "OTPLINK_INVALID_TOKEN",
    binding_mismatch: "OTPLINK_BINDING_MISMATCH",
    delivery_failed: "OTPLINK_DELIVERY_FAILED",
    configuration_error: "OTPLINK_DELIVERY_FAILED",
};

/**
 * Rethrows a protocol error as an HTTP one.
 *
 * Only `publicMessage` crosses the boundary. The internal `message` names the
 * exact reason a challenge failed — expired, consumed, never existed — and
 * handing that to a caller would tell an attacker holding a captured token
 * whether it was ever valid.
 */
function toApiError(error: unknown): never {
    if (!OtpLinkError.is(error)) throw error;

    const headers =
        error.retryAfter !== undefined ? { "Retry-After": String(error.retryAfter) } : undefined;

    throw new APIError(
        STATUS[error.code],
        {
            message: error.publicMessage,
            code: CODE_NAMES[error.code],
            ...(error.retryAfter !== undefined ? { retryAfter: error.retryAfter } : {}),
            ...(error.remainingAttempts !== undefined
                ? { remainingAttempts: error.remainingAttempts }
                : {}),
        },
        headers,
    );
}

/** A store that exists only to satisfy eager config validation. */
const UNUSABLE_STORE: TokenStore = {
    insert: () => Promise.reject(new Error("otplink: store not bound")),
    consume: () => Promise.reject(new Error("otplink: store not bound")),
    registerFailedAttempt: () => Promise.reject(new Error("otplink: store not bound")),
    delete: () => Promise.reject(new Error("otplink: store not bound")),
    countIssuedSince: () => Promise.reject(new Error("otplink: store not bound")),
    deleteExpired: () => Promise.reject(new Error("otplink: store not bound")),
};

const signInBody = object({
    email: string({ description: "Email address to send the code and link to", maxLength: 320 }),
    callbackURL: optional(
        string({ description: "Where to redirect after a successful sign-in", maxLength: 2048 }),
    ),
    name: optional(
        string({ description: "Display name, used only when registering", maxLength: 256 }),
    ),
    metadata: optional(record("Arbitrary data returned on successful verification")),
});

const verifyCodeBody = object({
    email: string({ description: "The address the code was sent to", maxLength: 320 }),
    code: string({ description: "The code from the email", maxLength: 64 }),
    callbackURL: optional(
        string({ description: "Where to redirect after a successful sign-in", maxLength: 2048 }),
    ),
});

const verifyTokenBody = object({
    token: string({ description: "The link token", maxLength: 512 }),
    callbackURL: optional(
        string({ description: "Where to redirect after a successful sign-in", maxLength: 2048 }),
    ),
});

const verifyQuery = object({
    token: string({ description: "The link token", maxLength: 512 }),
    callbackURL: optional(
        string({ description: "Where to redirect after a successful sign-in", maxLength: 2048 }),
    ),
});

export function otplink(options: OtplinkPluginOptions) {
    const model = options.model ?? DEFAULT_MODEL;
    const interstitialMode = options.interstitialMode ?? "auto";
    const defaultCallbackURL = options.defaultCallbackURL ?? "/";

    // Validate eagerly, at `betterAuth()` time, by building a throwaway
    // instance against a store that cannot be used. The whole point of
    // otplink validating its options in the constructor is that a weak
    // secret or an http:// baseUrl fails at startup rather than at 3am on a
    // sign-in path, and binding the real store needs a request-time adapter.
    // Constructing once here preserves the property; the instance is
    // discarded.
    createOtpLink({ ...options, store: UNUSABLE_STORE });

    // Better Auth builds its AuthContext once per `betterAuth()` call and
    // reuses it for every request, so the adapter is effectively a singleton
    // and memoizing on it is safe. The identity check is belt-and-braces for
    // hosts that rebuild the context.
    let instance: OtpLink | null = null;
    let boundTo: unknown = null;

    /** Resolves the request-scoped otplink instance. */
    function resolve(ctx: {
        context: { adapter: unknown; baseURL: string; options: { basePath?: string | undefined } };
    }): OtpLink {
        const adapter = ctx.context.adapter as BetterAuthAdapterLike;
        if (instance !== null && boundTo === adapter) return instance;

        instance = createOtpLink({
            ...options,
            store: createBetterAuthStore({ adapter, model }),
            // The email's link has to resolve to this plugin's endpoint,
            // wherever the host mounted Better Auth. Deriving it beats asking
            // the user to keep a second copy of their basePath in sync.
            verifyPath: options.verifyPath ?? mountedPath(ctx),
        });
        boundTo = adapter;
        return instance;
    }

    /** Absolute path of the verify endpoint, honouring `basePath`. */
    function mountedPath(ctx: {
        context: { baseURL: string; options: { basePath?: string | undefined } };
    }): string {
        const base = new URL(ctx.context.baseURL);
        const pathname = base.pathname === "/" ? "" : base.pathname;
        // `baseURL` usually already carries the basePath. Only append it when
        // it plainly does not, which mirrors how Better Auth's own plugins
        // reconstruct their URLs.
        const basePath = pathname ? "" : (ctx.context.options.basePath ?? "");
        return `${pathname}${basePath}/otplink/verify`;
    }

    function verifyEndpointUrl(ctx: {
        context: { baseURL: string; options: { basePath?: string | undefined } };
    }): string {
        return new URL(mountedPath(ctx), new URL(ctx.context.baseURL).origin).toString();
    }

    /**
     * Resolves a redirect target to an absolute, same-origin URL.
     *
     * `callbackURL` reaches this from a request body, so it is attacker
     * controlled and an unchecked redirect is an open redirect. Endpoints
     * that take one from the caller run Better Auth's `originCheck`
     * middleware, which honours `trustedOrigins`. This is the second line:
     * anything that resolves off-origin is discarded rather than followed,
     * which also covers the copy carried in challenge metadata, issued on an
     * earlier request that this one cannot re-validate.
     */
    function safeRedirect(ctx: { context: { baseURL: string } }, target: unknown): string {
        const fallback = new URL(defaultCallbackURL, ctx.context.baseURL).toString();
        if (typeof target !== "string" || target.length === 0) return fallback;

        try {
            const base = new URL(ctx.context.baseURL);
            const resolved = new URL(decodeURIComponent(target), base);
            return resolved.origin === base.origin ? resolved.toString() : fallback;
        } catch {
            return fallback;
        }
    }

    /**
     * Turns a verified address into a Better Auth session.
     *
     * Everything past this point is Better Auth's: user lookup, creation,
     * session rows, cookie flags, and rotation. otplink's contract ended at
     * "this request proved control of this address, just now".
     */
    async function establishSession(
        ctx: SessionContext,
        identity: VerifiedIdentity,
    ): Promise<{ user: Record<string, unknown>; session: Record<string, unknown>; isNewUser: boolean }> {
        const internal = ctx.context.internalAdapter;

        let user = await internal.findUserByEmail(identity.email).then((found) => found?.user);
        let isNewUser = false;

        if (!user) {
            if (options.disableSignUp) {
                throw new APIError("FORBIDDEN", {
                    message: OTPLINK_ERROR_CODES.OTPLINK_SIGNUP_DISABLED,
                    code: "OTPLINK_SIGNUP_DISABLED",
                });
            }
            const name = identity.metadata?.["name"];
            user = await internal.createUser({
                email: identity.email,
                emailVerified: true,
                name: typeof name === "string" ? name : "",
            });
            isNewUser = true;
        }

        // Redeeming either arm proves control of the address, which is
        // precisely what email verification asserts.
        if (!user.emailVerified) {
            user = await internal.updateUser(user.id, { emailVerified: true });
        }

        const session = await internal.createSession(user.id);
        if (!session) {
            throw new APIError("INTERNAL_SERVER_ERROR", { message: "Failed to create a session." });
        }

        await setSessionCookie(ctx, { session, user });
        return {
            user: user as unknown as Record<string, unknown>,
            session: session as unknown as Record<string, unknown>,
            isNewUser,
        };
    }

    const rateLimitWindow = options.rateLimit?.window ?? 60;
    const rateLimitMax = options.rateLimit?.max ?? 5;

    return {
        id: "otplink",
        schema: otplinkSchema({ model }),
        $ERROR_CODES: OTPLINK_ERROR_CODES,
        options,

        rateLimit: [
            {
                pathMatcher: (path: string) =>
                    path.startsWith("/sign-in/otplink") || path.startsWith("/otplink/verify"),
                window: rateLimitWindow,
                max: rateLimitMax,
            },
        ],

        endpoints: {
            /**
             * Issues one challenge carrying two independent secrets and mails
             * both. Always reports success: whether an address exists, and
             * whether `shouldSend` suppressed delivery, are not the caller's
             * business.
             */
            signInOtplink: createAuthEndpoint(
                "/sign-in/otplink",
                {
                    method: "POST",
                    body: signInBody,
                    requireHeaders: true,
                    use: [originCheck((ctx) => (ctx.body as { callbackURL?: string }).callbackURL ?? "/")],
                    metadata: {
                        openapi: {
                            operationId: "signInWithOtplink",
                            description: "Email a one-time code and a scanner-safe magic link",
                            responses: {
                                200: {
                                    description: "Success",
                                    content: {
                                        "application/json": {
                                            schema: {
                                                type: "object" as const,
                                                properties: {
                                                    status: { type: "boolean" },
                                                    expiresAt: { type: "number" },
                                                    codeLength: { type: "number" },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
                async (ctx) => {
                    const auth = resolve(ctx);
                    const body = ctx.body;

                    // The link is clicked later, possibly in another browser,
                    // so the intended destination has to travel with the
                    // challenge rather than with the request.
                    const metadata: Record<string, unknown> = { ...(body.metadata ?? {}) };
                    if (body.name !== undefined) metadata["name"] = body.name;
                    if (body.callbackURL !== undefined) metadata["callbackURL"] = body.callbackURL;

                    try {
                        const result = await auth.start({
                            email: body.email,
                            purpose: "sign-in",
                            metadata,
                            ...(ctx.request
                                ? { rateLimitKey: getIp(ctx.request, ctx.context.options) ?? "" }
                                : {}),
                        });

                        return ctx.json({
                            status: true,
                            expiresAt: result.expiresAt,
                            codeLength: result.codeLength,
                        });
                    } catch (error) {
                        return toApiError(error);
                    }
                },
            ),

            /** Redeems the typed code. */
            verifyOtplinkCode: createAuthEndpoint(
                "/sign-in/otplink/code",
                {
                    method: "POST",
                    body: verifyCodeBody,
                    requireHeaders: true,
                    use: [originCheck((ctx) => (ctx.body as { callbackURL?: string }).callbackURL ?? "/")],
                    metadata: {
                        openapi: {
                            operationId: "verifyOtplinkCode",
                            description: "Redeem the one-time code from an otplink email",
                        },
                    },
                },
                async (ctx) => {
                    const auth = resolve(ctx);

                    let identity: VerifiedIdentity;
                    try {
                        identity = await auth.verifyCode({
                            email: ctx.body.email,
                            code: ctx.body.code,
                            purpose: "sign-in",
                            ...(ctx.request
                                ? { rateLimitKey: getIp(ctx.request, ctx.context.options) ?? "" }
                                : {}),
                        });
                    } catch (error) {
                        return toApiError(error);
                    }

                    const { user, session, isNewUser } = await establishSession(
                        ctx as unknown as SessionContext,
                        identity,
                    );

                    const target = ctx.body.callbackURL ?? identity.metadata?.["callbackURL"];
                    if (ctx.body.callbackURL !== undefined) {
                        throw ctx.redirect(safeRedirect(ctx, target));
                    }

                    return ctx.json({
                        status: true,
                        isNewUser,
                        token: (session as { token?: string }).token,
                        user,
                        session,
                    });
                },
            ),

            /**
             * The confirmation page. Consumes nothing.
             *
             * This endpoint is the entire reason the plugin exists. RFC 9110
             * requires `GET` to be safe, and spending a one-time credential is
             * about as unsafe as a request gets — which is why Defender Safe
             * Links, Proofpoint, Mimecast, and Barracuda prefetching every URL
             * in inbound mail destroys a conventional magic link. Here they
             * fetch an HTML page, and the token stays live for the human.
             */
            otplinkVerifyPage: createAuthEndpoint(
                "/otplink/verify",
                {
                    method: "GET",
                    query: verifyQuery,
                    metadata: {
                        openapi: {
                            operationId: "otplinkConfirmPage",
                            description:
                                "Renders the sign-in confirmation page. Safe: consumes nothing.",
                        },
                    },
                },
                async (ctx) => {
                    const nonce = createNonce();
                    const action = verifyEndpointUrl(ctx);

                    const html = renderInterstitial({
                        token: ctx.query.token,
                        action,
                        product: options.email?.product ?? "your account",
                        mode: interstitialMode,
                        nonce,
                    });

                    // Returned rather than thrown, and with `no-store` plus a
                    // nonce-scoped CSP: the token is in this document, so it
                    // must not be cached, indexed, framed, or reachable by an
                    // injected script.
                    return new Response(html, { status: 200, headers: securityHeaders(nonce) });
                },
            ),

            /** Redeems the link token. Only this consumes it. */
            otplinkVerify: createAuthEndpoint(
                "/otplink/verify",
                {
                    method: "POST",
                    body: verifyTokenBody,
                    requireHeaders: true,
                    use: [originCheck((ctx) => (ctx.body as { callbackURL?: string }).callbackURL ?? "/")],
                    metadata: {
                        openapi: {
                            operationId: "verifyOtplinkToken",
                            description: "Redeem the magic-link token from an otplink email",
                        },
                    },
                },
                async (ctx) => {
                    const auth = resolve(ctx);

                    let identity: VerifiedIdentity;
                    try {
                        identity = await auth.verifyToken({
                            token: ctx.body.token,
                            ...(ctx.request
                                ? { rateLimitKey: getIp(ctx.request, ctx.context.options) ?? "" }
                                : {}),
                        });
                    } catch (error) {
                        return toApiError(error);
                    }

                    // The session cookie is set on `ctx`, so it rides along on
                    // the redirect response below.
                    await establishSession(ctx as unknown as SessionContext, identity);

                    // The link flow is a browser navigation, so it always
                    // redirects rather than returning JSON. The destination
                    // was captured when the challenge was issued, because the
                    // click can happen in a different browser entirely.
                    const target = ctx.body.callbackURL ?? identity.metadata?.["callbackURL"];
                    throw ctx.redirect(safeRedirect(ctx, target));
                },
            ),
        },
    };
}
