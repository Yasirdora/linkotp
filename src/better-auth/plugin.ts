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

import { APIError, createAuthEndpoint, getIP, isAPIError, originCheck } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";

import type { OtpLinkOptions } from "../config.ts";
import { createOtpLink, type OtpLink } from "../core.ts";
import { OtpLinkError, type OtpLinkErrorCode } from "../errors.ts";
import { createNonce, renderInterstitial, securityHeaders } from "../http/interstitial.ts";
import type { TokenStore, VerifiedIdentity } from "../types.ts";
import { OTPLINK_ERROR_CODES } from "./error-codes.ts";
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

    /**
     * Where to send the browser when a link *fails*, with `?error=<code>`
     * appended.
     *
     * This is not an edge case. A link that has expired, been redeemed, or
     * been retired by too many wrong code guesses is the ordinary end of a
     * challenge's life, and the person clicking it is in a browser, not an
     * XHR. Without somewhere to land they are shown a raw JSON error body.
     *
     * @default the value of `defaultCallbackURL`
     */
    readonly errorCallbackURL?: string;

    /** Per-path throttle Better Auth applies in front of the endpoints. */
    readonly rateLimit?: { readonly window?: number; readonly max?: number };
}

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
    errorCallbackURL: optional(
        string({ description: "Where to redirect when the link is no longer valid", maxLength: 2048 }),
    ),
});

// No `callbackURL` here on purpose. The click can land in a different browser
// from the one that started the flow, so the destination travels with the
// challenge rather than with the link, and accepting a query parameter the
// page then dropped would be surface that quietly does nothing.
const verifyQuery = object({
    token: string({ description: "The link token", maxLength: 512 }),
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
     * Derives otplink's per-caller rate-limit dimension, conventionally the IP.
     *
     * Returned as a spreadable fragment so an unresolvable client is *absent*
     * rather than empty. The distinction matters: otplink skips throttling
     * when the key is `undefined`, but an empty string is a perfectly valid
     * key, and every caller sharing it would collapse them into a single
     * bucket — the first few requests would then rate-limit everyone else.
     * `getIP` returns null whenever `disableIpTracking` is set or no
     * trustworthy address can be resolved from the forwarded chain, so this
     * is a live path, not a theoretical one.
     */
    function clientKey(ctx: {
        request?: Request | undefined;
        context: { options: Parameters<typeof getIP>[1] };
    }): { rateLimitKey?: string } {
        if (!ctx.request) return {};
        const ip = getIP(ctx.request, ctx.context.options);
        return ip ? { rateLimitKey: ip } : {};
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
                    message: OTPLINK_ERROR_CODES.OTPLINK_SIGNUP_DISABLED.message,
                    code: "OTPLINK_SIGNUP_DISABLED",
                });
            }
            const name = identity.metadata?.["name"];
            user = await internal.createUser(
                {
                    email: identity.email,
                    emailVerified: true,
                    name: typeof name === "string" ? name : "",
                },
                // Report the arm the user actually redeemed rather than a
                // label of our own. `ValidateUserInfoMethod` accepts an
                // arbitrary string, but an application's `validateUserInfo`
                // gate is written against the known ones, and an otplink
                // challenge genuinely *is* a magic link and a one-time code —
                // which of the two provisioned this account is the honest and
                // more useful answer.
                { method: identity.via === "link" ? "magic-link" : "email-otp" },
            );
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
                            ...clientKey(ctx),
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
                            ...clientKey(ctx),
                        });
                    } catch (error) {
                        return toApiError(error);
                    }

                    const { user, session, isNewUser } = await establishSession(
                        ctx as unknown as SessionContext,
                        identity,
                    );

                    // The code flow is normally an XHR, so it answers with
                    // JSON unless the caller explicitly asked to be redirected.
                    if (ctx.body.callbackURL !== undefined) {
                        throw ctx.redirect(safeRedirect(ctx, ctx.body.callbackURL));
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
                        // The confirmation page is plain HTML submitting a
                        // plain form, so this arrives as
                        // `application/x-www-form-urlencoded`. Better Auth's
                        // router allows JSON only by default and answers
                        // anything else with 415, which would reject the
                        // submission that is the entire point of the
                        // GET/POST split. Opting in mirrors what the
                        // device-authorization flow does for the same reason.
                        //
                        // A no-JavaScript form post is also the fallback that
                        // makes the "manual" interstitial mode work at all.
                        allowedMediaTypes: [
                            "application/json",
                            "application/x-www-form-urlencoded",
                        ],
                        openapi: {
                            operationId: "verifyOtplinkToken",
                            description: "Redeem the magic-link token from an otplink email",
                        },
                    },
                },
                async (ctx) => {
                    const auth = resolve(ctx);

                    /**
                     * Ends the request at the error page rather than on a JSON
                     * error body.
                     *
                     * Everything reaching this endpoint arrived by a human
                     * clicking a link, and the failure modes are ordinary:
                     * the challenge expired, someone already redeemed it, or
                     * the code arm burned its attempts. A 400 rendered as raw
                     * JSON is the wrong answer to all of them.
                     */
                    const fail = (code: string): never => {
                        const target =
                            ctx.body.errorCallbackURL ??
                            options.errorCallbackURL ??
                            defaultCallbackURL;
                        const url = new URL(safeRedirect(ctx, target));
                        url.searchParams.set("error", code);
                        throw ctx.redirect(url.toString());
                    };

                    let identity: VerifiedIdentity;
                    try {
                        identity = await auth.verifyToken({
                            token: ctx.body.token,
                            ...clientKey(ctx),
                        });
                    } catch (error) {
                        // Expired, already used, and never existed are one
                        // code by design: distinguishing them would tell
                        // someone holding a captured token whether it was
                        // ever valid.
                        if (OtpLinkError.is(error)) fail(error.code);
                        throw error;
                    }

                    try {
                        // The session cookie is set on `ctx`, so it rides
                        // along on the redirect response below.
                        await establishSession(ctx as unknown as SessionContext, identity);
                    } catch (error) {
                        // `disableSignUp`, or an application's own
                        // `validateUserInfo` gate, rejects here. Same
                        // reasoning: the browser needs a page, not a body.
                        if (isAPIError(error)) {
                            fail(
                                typeof error.body?.code === "string"
                                    ? error.body.code
                                    : "sign_in_failed",
                            );
                        }
                        throw error;
                    }

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
