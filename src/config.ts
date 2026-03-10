/**
 * Option parsing, validation, and defaults.
 *
 * Configuration is validated once, eagerly, at `createOtpLink` time. A
 * misconfigured deployment fails at startup with an actionable message rather
 * than at 3am on a sign-in path, and several of these checks (secret length,
 * token entropy) are the difference between a sound deployment and a quietly
 * weak one.
 */

import { createHasher, entropyBits, type Hasher } from "./crypto.ts";
import { OtpLinkError } from "./errors.ts";
import type { Mailer, Purpose, RateLimiter, TokenStore } from "./types.ts";

/** Ambiguity-free code alphabet: no I, O, 0, or 1 to mistype over the phone. */
export const DEFAULT_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
export const DEFAULT_CODE_LENGTH = 6;

/** Full alphanumeric for link tokens, which are never read aloud. */
export const DEFAULT_TOKEN_ALPHABET =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
export const DEFAULT_TOKEN_LENGTH = 48;

/** Below this, a stolen database plus commodity hardware recovers the secret. */
const MIN_SECRET_LENGTH = 32;
/** A link token is a bearer credential; hold it to session-token strength. */
const MIN_TOKEN_ENTROPY_BITS = 128;
/** A code is rate-limited and short-lived, so it can be far weaker, but not free. */
const MIN_CODE_ENTROPY_BITS = 20;

export interface SecretRotation {
    /**
     * Previously active secrets, newest first. Digests are always written
     * under the current secret, and verification falls back through this list
     * on read, so rotating does not invalidate challenges already in flight.
     * Drop an entry once one full TTL has elapsed since the rotation.
     */
    readonly previous: readonly string[];
}

export interface SecretShape {
    readonly length?: number;
    readonly alphabet?: string;
}

export interface RenderContext {
    readonly email: string;
    readonly code: string;
    readonly url: string;
    readonly product: string;
    readonly purpose: Purpose;
    readonly ttlMinutes: number;
    readonly metadata: Readonly<Record<string, unknown>> | null;
}

export interface EmailOptions {
    /** Product name shown in the subject and body. */
    readonly product?: string;
    /** Subject line builder. */
    readonly subject?: (context: { product: string; purpose: Purpose }) => string;
    /** Replaces the bundled template wholesale. */
    readonly render?: (context: RenderContext) => { html: string; text: string };
}

export interface BindingOptions {
    /**
     * Ties a challenge to the browser that requested it, so the link only
     * works there.
     *
     * This closes real attacks: a forwarded email, a shoulder-surfed inbox, a
     * compromised mail server. It also breaks the common "request on laptop,
     * click on phone" flow, and a mismatch burns the challenge rather than
     * offering a retry, because a mismatch means someone other than the
     * initiator presented the secret. Off by default; turn it on where the
     * threat model warrants it.
     *
     * @default false
     */
    readonly enabled: boolean;
}

export interface OtpLinkOptions {
    /**
     * Application secret keying every stored digest. At least 32 characters
     * of high entropy, read from the environment, never a literal in source.
     *
     * Generate one with:
     * `node -e "console.log(crypto.randomBytes(32).toString('base64url'))"`
     */
    readonly secret: string;
    /** Previous secrets, to rotate without invalidating live challenges. */
    readonly rotation?: SecretRotation;
    /** Origin the verification link points at, e.g. `https://example.com`. */
    readonly baseUrl: string;
    /** Path the link resolves to. Must be absolute. @default "/auth/verify" */
    readonly verifyPath?: string;

    readonly store: TokenStore;
    readonly mailer: Mailer;

    /** Challenge lifetime. @default 900 (15 minutes) */
    readonly ttlSeconds?: number;
    /** Failed code submissions before the challenge dies. @default 5 */
    readonly maxAttempts?: number;

    readonly code?: SecretShape;
    readonly token?: SecretShape;
    readonly email?: EmailOptions;
    readonly binding?: BindingOptions;

    /**
     * Per-address send cap, so one address cannot be mailbombed through a
     * public sign-in form. @default 5 sends per TTL window
     */
    readonly maxSendsPerAddress?: { readonly count: number; readonly windowSeconds: number };

    /** Optional external throttle, consulted before issuing and verifying. */
    readonly rateLimiter?: RateLimiter;

    /**
     * Gate on whether to actually deliver. Return false to skip silently.
     *
     * This is how you close sign-ups without leaking which addresses have
     * accounts: `start` returns an identical result and takes an
     * indistinguishable amount of time either way, so a caller probing the
     * endpoint learns nothing. Never surface the boolean to the client.
     */
    readonly shouldSend?: (
        email: string,
        context: { purpose: Purpose; metadata: Readonly<Record<string, unknown>> | null },
    ) => Promise<boolean> | boolean;

    /**
     * Floor on how long `start` takes, in milliseconds, so a suppressed send
     * is indistinguishable from a real one. Set 0 to disable.
     * @default 500
     */
    readonly minimumStartDurationMs?: number;

    /** Injectable clock. Tests pass a fake; production leaves this unset. */
    readonly clock?: () => number;
}

/** Fully defaulted, validated configuration. Holds no plaintext secret. */
export interface ResolvedConfig {
    readonly hash: Hasher;
    readonly fallbackHashers: readonly Hasher[];
    readonly baseUrl: string;
    readonly verifyPath: string;
    readonly store: TokenStore;
    readonly mailer: Mailer;
    readonly ttlMs: number;
    readonly maxAttempts: number;
    readonly code: { readonly length: number; readonly alphabet: string };
    readonly token: { readonly length: number; readonly alphabet: string };
    readonly product: string;
    readonly subject: (context: { product: string; purpose: Purpose }) => string;
    readonly render: EmailOptions["render"];
    readonly bindingEnabled: boolean;
    readonly maxSendsPerAddress: { readonly count: number; readonly windowMs: number };
    readonly rateLimiter: RateLimiter | undefined;
    readonly shouldSend: OtpLinkOptions["shouldSend"];
    readonly minimumStartDurationMs: number;
    readonly clock: () => number;
}

function fail(message: string): never {
    throw new OtpLinkError("configuration_error", message);
}

function resolveSecretShape(kind: "code" | "token", shape: SecretShape | undefined) {
    const isCode = kind === "code";
    const length = shape?.length ?? (isCode ? DEFAULT_CODE_LENGTH : DEFAULT_TOKEN_LENGTH);
    const alphabet = shape?.alphabet ?? (isCode ? DEFAULT_CODE_ALPHABET : DEFAULT_TOKEN_ALPHABET);

    if (!Number.isInteger(length) || length < 1) {
        fail(`${kind}.length must be a positive integer`);
    }
    if (alphabet.length < 2) {
        fail(`${kind}.alphabet needs at least 2 characters`);
    }
    if (new Set(alphabet).size !== alphabet.length) {
        fail(`${kind}.alphabet contains duplicate characters, which skews the distribution`);
    }

    const bits = entropyBits(length, alphabet.length);
    const floor = isCode ? MIN_CODE_ENTROPY_BITS : MIN_TOKEN_ENTROPY_BITS;
    if (bits < floor) {
        fail(
            `${kind} entropy is ${bits.toFixed(1)} bits, below the ${floor}-bit minimum. ` +
                (isCode
                    ? "A code this short is guessable even with attempt limiting. " +
                      "Use at least 6 characters over a 32-character alphabet."
                    : "A link token is a bearer credential and needs session-token " +
                      "strength. Use at least 22 alphanumeric characters."),
        );
    }

    return { length, alphabet };
}

export function resolveOptions(options: OtpLinkOptions): ResolvedConfig {
    if (typeof options?.secret !== "string" || options.secret.length < MIN_SECRET_LENGTH) {
        fail(
            `secret must be a string of at least ${MIN_SECRET_LENGTH} characters. Generate ` +
                `one with: node -e "console.log(crypto.randomBytes(32).toString('base64url'))"`,
        );
    }
    if (options.rotation?.previous.some((s) => typeof s !== "string" || s.length === 0)) {
        fail("rotation.previous must contain only non-empty strings");
    }

    let origin: string;
    try {
        const parsed = new URL(options.baseUrl);
        const isLoopback = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
        if (parsed.protocol !== "https:" && !isLoopback) {
            fail(
                "baseUrl must be https outside local development. A magic link sent over " +
                    `http is readable by anyone on the network path. Got: ${parsed.protocol}//${parsed.host}`,
            );
        }
        origin = parsed.origin;
    } catch (error) {
        if (OtpLinkError.is(error)) throw error;
        fail(`baseUrl is not a valid absolute URL: ${String(options.baseUrl)}`);
    }

    const verifyPath = options.verifyPath ?? "/auth/verify";
    if (!verifyPath.startsWith("/") || verifyPath.startsWith("//")) {
        fail('verifyPath must be an absolute same-origin path beginning with "/"');
    }

    const ttlSeconds = options.ttlSeconds ?? 900;
    if (!Number.isFinite(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 86_400) {
        fail("ttlSeconds must be between 60 and 86400 (1 minute to 24 hours)");
    }

    const maxAttempts = options.maxAttempts ?? 5;
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 100) {
        fail("maxAttempts must be an integer between 1 and 100");
    }

    if (typeof options.store?.consume !== "function") {
        fail("store is missing or does not implement the TokenStore interface");
    }
    if (typeof options.mailer !== "function") {
        fail("mailer must be a function of (message, context)");
    }

    const sends = options.maxSendsPerAddress ?? { count: 5, windowSeconds: ttlSeconds };
    if (!Number.isInteger(sends.count) || sends.count < 1) {
        fail("maxSendsPerAddress.count must be a positive integer");
    }
    if (!Number.isFinite(sends.windowSeconds) || sends.windowSeconds < 1) {
        fail("maxSendsPerAddress.windowSeconds must be at least 1");
    }

    const minimumStartDurationMs = options.minimumStartDurationMs ?? 500;
    if (!Number.isFinite(minimumStartDurationMs) || minimumStartDurationMs < 0) {
        fail("minimumStartDurationMs must be a non-negative number");
    }

    // The plaintext secret is captured inside the hasher closures and
    // deliberately not retained on the returned object, so no accidental
    // JSON.stringify of the config, and no error serialization, can leak it.
    const config: ResolvedConfig = {
        hash: createHasher(options.secret),
        fallbackHashers: Object.freeze(
            (options.rotation?.previous ?? []).map((secret) => createHasher(secret)),
        ),
        baseUrl: origin,
        verifyPath,
        store: options.store,
        mailer: options.mailer,
        ttlMs: ttlSeconds * 1000,
        maxAttempts,
        code: Object.freeze(resolveSecretShape("code", options.code)),
        token: Object.freeze(resolveSecretShape("token", options.token)),
        product: options.email?.product ?? "your account",
        subject:
            options.email?.subject ?? (({ product }) => `Your sign-in code for ${product}`),
        render: options.email?.render,
        bindingEnabled: options.binding?.enabled ?? false,
        maxSendsPerAddress: Object.freeze({
            count: sends.count,
            windowMs: sends.windowSeconds * 1000,
        }),
        rateLimiter: options.rateLimiter,
        shouldSend: options.shouldSend,
        minimumStartDurationMs,
        clock: options.clock ?? Date.now,
    };

    return Object.freeze(config);
}

/**
 * Pragmatic address validation.
 *
 * Full RFC 5322 validation is neither achievable with a regular expression
 * nor useful: addresses that parse can still bounce, and addresses that fail
 * a strict grammar are routinely deliverable. This checks the properties that
 * actually matter for safety, then lets delivery be the real test. A single
 * at-sign, a non-empty local part, a dotted domain, no whitespace or control
 * characters, and a length within the SMTP limit.
 */
const EMAIL_PATTERN = /^[^\s@,;<>"]+@[^\s@,;<>".]+(\.[^\s@,;<>".]+)+$/u;
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/u;
const MAX_EMAIL_LENGTH = 254;

export function normalizeEmail(raw: unknown): string | null {
    if (typeof raw !== "string") return null;
    const trimmed = raw.trim();
    if (trimmed.length === 0 || trimmed.length > MAX_EMAIL_LENGTH) return null;
    if (CONTROL_CHARS.test(trimmed)) return null;
    if (!EMAIL_PATTERN.test(trimmed)) return null;

    // Lowercasing the domain is unambiguously correct. Lowercasing the local
    // part is technically lossy, since RFC 5321 declares it case-sensitive,
    // but every mainstream provider treats it case-insensitively and
    // preserving case means User@x.com and user@x.com become two accounts.
    //
    // We deliberately do NOT strip dots or +tags. Those rules are
    // provider-specific, and applying Gmail's to a corporate domain silently
    // merges distinct people into a single account.
    return trimmed.toLowerCase();
}

/** Strips formatting the user may have typed and upcases into the alphabet. */
export function normalizeCode(raw: unknown, alphabet: string): string {
    if (typeof raw !== "string") return "";
    const allowed = new Set(alphabet);
    let out = "";
    for (const char of raw.toUpperCase()) {
        if (allowed.has(char)) out += char;
    }
    return out;
}
