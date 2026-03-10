/**
 * The protocol.
 *
 * `start` issues one challenge carrying two independent secrets: a short code
 * the user types, and a long token they click. `verifyCode` and `verifyToken`
 * each redeem exactly one of them, atomically and at most once.
 *
 * What this module deliberately does not do is create a session. Minting
 * sessions means owning cookie flags, rotation, revocation, CSRF, and device
 * management, and every application already has opinions about all of those.
 * The contract here ends at a single verified claim: this request proved
 * control of this address, just now. What you do with that is yours.
 */

import {
    normalizeCode,
    normalizeEmail,
    resolveOptions,
    type OtpLinkOptions,
    type ResolvedConfig,
} from "./config.ts";
import { randomId, randomString, timingSafeEqual, type Hasher } from "./crypto.ts";
import { renderDefaultTemplate, RECOMMENDED_HEADERS } from "./email.ts";
import { OtpLinkError } from "./errors.ts";
import type { Challenge, ConsumeQuery, Purpose, StartResult, VerifiedIdentity } from "./types.ts";

export interface StartInput {
    readonly email: string;
    /** @default "sign-in" */
    readonly purpose?: Purpose;
    /** Returned verbatim on success. Never included in the email. */
    readonly metadata?: Readonly<Record<string, unknown>>;
    /**
     * Opaque value identifying the requesting browser, when binding is on.
     * The HTTP layer supplies a cookie value; a custom caller can supply
     * anything stable and unguessable.
     */
    readonly binding?: string;
    /** Extra rate-limit dimension, conventionally the client IP. */
    readonly rateLimitKey?: string;
    readonly signal?: AbortSignal;
}

export interface VerifyCodeInput {
    readonly email: string;
    readonly code: string;
    /** @default "sign-in" */
    readonly purpose?: Purpose;
    readonly binding?: string;
    readonly rateLimitKey?: string;
}

export interface VerifyTokenInput {
    readonly token: string;
    readonly binding?: string;
    readonly rateLimitKey?: string;
}

/** Read-only view the HTTP layer needs. Exposes no secrets. */
export interface PublicConfig {
    readonly codeLength: number;
    readonly verifyPath: string;
    readonly baseUrl: string;
    readonly ttlMs: number;
    readonly maxAttempts: number;
    readonly bindingEnabled: boolean;
}

export interface OtpLink {
    /** Issues a challenge and delivers it. */
    start(input: StartInput): Promise<StartResult>;
    /** Redeems the typed code. */
    verifyCode(input: VerifyCodeInput): Promise<VerifiedIdentity>;
    /** Redeems the clicked link token. */
    verifyToken(input: VerifyTokenInput): Promise<VerifiedIdentity>;
    /** Deletes expired rows. Housekeeping only; expiry is enforced regardless. */
    sweep(): Promise<number>;
    readonly config: PublicConfig;
}

const sleep = (ms: number): Promise<void> =>
    ms <= 0 ? Promise.resolve() : new Promise((resolve) => setTimeout(resolve, ms));

export function createOtpLink(options: OtpLinkOptions): OtpLink {
    const config = resolveOptions(options);

    // Current hasher first, then any rotated-out secrets. Writes always use
    // the first; reads walk the list so challenges issued under a previous
    // secret stay redeemable until they expire.
    const hashers: readonly Hasher[] = [config.hash, ...config.fallbackHashers];

    const publicConfig: PublicConfig = Object.freeze({
        codeLength: config.code.length,
        verifyPath: config.verifyPath,
        baseUrl: config.baseUrl,
        ttlMs: config.ttlMs,
        maxAttempts: config.maxAttempts,
        bindingEnabled: config.bindingEnabled,
    });

    async function enforceRateLimit(scope: string, key: string | undefined): Promise<void> {
        if (!config.rateLimiter || key === undefined) return;
        const verdict = await config.rateLimiter.check(`otplink:${scope}:${key}`, config.clock());
        if (!verdict.allowed) {
            throw new OtpLinkError(
                "rate_limited",
                `rate limit exceeded for ${scope}`,
                verdict.retryAfter !== undefined ? { retryAfter: verdict.retryAfter } : {},
            );
        }
    }

    /**
     * Walks the hasher list attempting an atomic claim under each.
     *
     * Returns the claimed challenge along with the hasher that matched, which
     * the binding check then reuses so it compares digests computed under the
     * same secret the challenge was issued with.
     */
    async function claim(
        build: (hash: Hasher) => Promise<ConsumeQuery>,
    ): Promise<{ challenge: Challenge; hash: Hasher } | null> {
        for (const hash of hashers) {
            const claimed = await config.store.consume(await build(hash));
            if (claimed) return { challenge: claimed, hash };
        }
        return null;
    }

    /**
     * Verifies device binding against an already-claimed challenge.
     *
     * Runs after the claim, not before, which means a mismatch burns the
     * challenge. That is deliberate: a mismatch means someone other than the
     * initiator presented the secret, and retiring it is the correct response
     * rather than offering the presenter another try.
     */
    async function assertBinding(
        challenge: Challenge,
        hash: Hasher,
        presented: string | undefined,
    ): Promise<void> {
        // A null bindingHash means the challenge was issued while binding was
        // off. Skipping the check keeps a rollout from invalidating in-flight
        // challenges, and is safe because the field is set at issue time and
        // is never attacker-influenced.
        if (!config.bindingEnabled || challenge.bindingHash === null) return;

        if (presented === undefined || presented.length === 0) {
            throw new OtpLinkError(
                "binding_mismatch",
                "challenge is bound but no binding was presented",
            );
        }
        const presentedHash = await hash("binding", presented);
        if (!timingSafeEqual(presentedHash, challenge.bindingHash)) {
            throw new OtpLinkError("binding_mismatch", "binding does not match the issuing device");
        }
    }

    function identify(challenge: Challenge, via: "code" | "link", at: number): VerifiedIdentity {
        return Object.freeze({
            email: challenge.email,
            purpose: challenge.purpose,
            metadata: challenge.metadata,
            via,
            verifiedAt: at,
            challengeId: challenge.id,
        });
    }

    async function start(input: StartInput): Promise<StartResult> {
        const beganAt = Date.now();

        try {
            input.signal?.throwIfAborted();

            const email = normalizeEmail(input.email);
            if (email === null) {
                throw new OtpLinkError("invalid_email", "email failed validation");
            }

            const purpose: Purpose = input.purpose ?? "sign-in";
            const metadata = input.metadata ?? null;
            const now = config.clock();

            await enforceRateLimit("start", input.rateLimitKey);
            await enforceRateLimit("start-address", email);

            const issued = await config.store.countIssuedSince({
                email,
                purpose,
                since: now - config.maxSendsPerAddress.windowMs,
            });
            if (issued >= config.maxSendsPerAddress.count) {
                throw new OtpLinkError("rate_limited", "per-address send cap reached", {
                    retryAfter: Math.ceil(config.maxSendsPerAddress.windowMs / 1000),
                });
            }

            // The suppression decision produces an identical return value
            // either way, so a caller probing the endpoint learns nothing.
            const permitted = (await config.shouldSend?.(email, { purpose, metadata })) ?? true;

            const expiresAt = now + config.ttlMs;
            if (!permitted) {
                return Object.freeze({
                    sent: true as const,
                    expiresAt,
                    codeLength: config.code.length,
                });
            }

            const code = randomString(config.code.length, config.code.alphabet);
            const token = randomString(config.token.length, config.token.alphabet);

            const challenge: Challenge = Object.freeze({
                id: randomId(),
                email,
                purpose,
                // Salting the code digest with the address means a digest
                // captured for one account can never be replayed against
                // another, even if a store implementation loosened its lookup.
                codeHash: await config.hash("code", codePayload(email, code)),
                tokenHash: await config.hash("token", token),
                bindingHash:
                    config.bindingEnabled && input.binding
                        ? await config.hash("binding", input.binding)
                        : null,
                metadata,
                attempts: 0,
                maxAttempts: config.maxAttempts,
                createdAt: now,
                expiresAt,
                consumedAt: null,
            });

            await config.store.insert(challenge);

            const url = new URL(config.verifyPath, config.baseUrl);
            url.searchParams.set("token", token);

            const body = (config.render ?? renderDefaultTemplate)({
                email,
                code,
                url: url.toString(),
                product: config.product,
                purpose,
                ttlMinutes: Math.round(config.ttlMs / 60_000),
                metadata,
            });

            try {
                await config.mailer(
                    {
                        to: email,
                        subject: config.subject({ product: config.product, purpose }),
                        html: body.html,
                        text: body.text,
                        headers: RECOMMENDED_HEADERS,
                    },
                    { purpose, metadata, signal: input.signal },
                );
            } catch (error) {
                // Roll the challenge back so a transport outage does not eat
                // the caller's send quota or leave a live secret nobody has.
                // Best effort: the delivery failure is the error worth raising.
                await config.store.delete(challenge.id).catch(() => undefined);
                throw new OtpLinkError("delivery_failed", "mailer threw", { cause: error });
            }

            return Object.freeze({
                sent: true as const,
                expiresAt,
                codeLength: config.code.length,
            });
        } finally {
            // Equalizes the fast paths (validation reject, suppressed send)
            // against the slow one (an actual delivery), so response latency
            // does not reveal whether an address is known. This raises the
            // floor; it does not make the paths identical, because a genuinely
            // slow transport still stands out. Queue delivery rather than
            // awaiting it if you need the timing to be truly flat.
            await sleep(config.minimumStartDurationMs - (Date.now() - beganAt));
        }
    }

    async function verifyCode(input: VerifyCodeInput): Promise<VerifiedIdentity> {
        const email = normalizeEmail(input.email);
        if (email === null) {
            throw new OtpLinkError("invalid_email", "email failed validation");
        }

        const purpose: Purpose = input.purpose ?? "sign-in";
        const code = normalizeCode(input.code, config.code.alphabet);

        await enforceRateLimit("verify", input.rateLimitKey);
        await enforceRateLimit("verify-address", email);

        const now = config.clock();

        // A malformed code can never match, but it must still burn an attempt.
        // Short-circuiting here would let an attacker probe for free.
        const claimed =
            code.length === config.code.length
                ? await claim(async (hash) => ({
                      by: "code" as const,
                      email,
                      purpose,
                      codeHash: await hash("code", codePayload(email, code)),
                      now,
                  }))
                : null;

        if (!claimed) {
            const outcome = await config.store.registerFailedAttempt({ email, purpose, now });

            // Exhaustion and absence are different messages. "Too many
            // attempts" tells someone to request a new code; saying it when no
            // challenge exists at all would be simply wrong, and saying "wrong
            // code" once the budget is spent sends them round a loop they can
            // never complete.
            if (outcome.found && outcome.remaining <= 0) {
                throw new OtpLinkError("too_many_attempts", "attempt ceiling reached", {
                    remainingAttempts: 0,
                });
            }
            throw new OtpLinkError("invalid_code", "no live challenge matched", {
                ...(outcome.found ? { remainingAttempts: outcome.remaining } : {}),
            });
        }

        await assertBinding(claimed.challenge, claimed.hash, input.binding);
        return identify(claimed.challenge, "code", now);
    }

    async function verifyToken(input: VerifyTokenInput): Promise<VerifiedIdentity> {
        await enforceRateLimit("verify", input.rateLimitKey);

        const now = config.clock();
        const token = typeof input.token === "string" ? input.token : "";

        const claimed = token
            ? await claim(async (hash) => ({
                  by: "token" as const,
                  tokenHash: await hash("token", token),
                  now,
              }))
            : null;

        if (!claimed) {
            // Expired, already used, and never existed are one error on
            // purpose. Distinguishing them would tell an attacker holding a
            // captured token whether it was ever valid.
            throw new OtpLinkError("invalid_token", "no live challenge matched");
        }

        await assertBinding(claimed.challenge, claimed.hash, input.binding);
        return identify(claimed.challenge, "link", now);
    }

    return Object.freeze({
        start,
        verifyCode,
        verifyToken,
        sweep: () => config.store.deleteExpired(config.clock()),
        config: publicConfig,
    });
}

/**
 * Binds a code digest to its address.
 *
 * The separator is a character the code alphabet excludes and a normalized
 * address cannot contain, so the concatenation is unambiguous and no pair of
 * distinct (email, code) inputs can produce the same payload.
 */
function codePayload(email: string, code: string): string {
    return `${email}|${code}`;
}

export type { ResolvedConfig };
