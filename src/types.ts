/**
 * Public type surface.
 *
 * The contracts declared here — particularly {@link TokenStore.consume} — are
 * load-bearing for the library's security properties. Read the doc comments
 * before writing a custom adapter, and run the bundled conformance suite
 * (`linkotp/testing`) against it.
 */

/** What a challenge is for. Free-form; carried through to the verified result. */
export type Purpose = "sign-in" | "sign-up" | "verify-email" | (string & {});

/**
 * One issued challenge: a code the user can type and a token they can click,
 * both bound to a single email address and a single expiry.
 *
 * The plaintext code and token are never stored. `codeHash` and `tokenHash`
 * hold keyed digests (see `createHasher`), so the row is inert to an attacker
 * who obtains the database but not the application secret.
 */
export interface Challenge {
    /** Opaque primary key. */
    readonly id: string;
    /** Normalized (lowercased, trimmed) address the challenge was issued to. */
    readonly email: string;
    readonly purpose: Purpose;
    /** Keyed digest of the typed code, domain-separated and salted by email. */
    readonly codeHash: string;
    /** Keyed digest of the link token. */
    readonly tokenHash: string;
    /** Keyed digest of the device-binding value, or null when binding is off. */
    readonly bindingHash: string | null;
    /** Caller-supplied payload returned verbatim on success. Never sent by email. */
    readonly metadata: Readonly<Record<string, unknown>> | null;
    /** Failed code submissions so far. */
    readonly attempts: number;
    /** Ceiling for `attempts`; once reached the challenge is permanently dead. */
    readonly maxAttempts: number;
    /** Epoch milliseconds. */
    readonly createdAt: number;
    /** Epoch milliseconds. */
    readonly expiresAt: number;
    /** Epoch milliseconds, or null while the challenge is still live. */
    readonly consumedAt: number | null;
}

/** Result of {@link TokenStore.registerFailedAttempt}. */
export interface FailedAttemptOutcome {
    /** Whether any unconsumed, unexpired challenge exists for the address. */
    readonly found: boolean;
    /** Attempts left on the challenge, floored at 0. Meaningless when `found` is false. */
    readonly remaining: number;
}

/** Lookup discriminator for {@link TokenStore.consume}. */
export type ConsumeQuery =
    | {
          readonly by: "token";
          readonly tokenHash: string;
          readonly now: number;
      }
    | {
          readonly by: "code";
          readonly email: string;
          readonly purpose: Purpose;
          readonly codeHash: string;
          readonly now: number;
      };

/**
 * Persistence adapter.
 *
 * Implementations ship for in-memory use and for any SQL database reachable
 * through a four-method driver. Anything else — Redis, DynamoDB, Durable
 * Objects — is a matter of satisfying this interface.
 */
export interface TokenStore {
    /**
     * Persists a freshly issued challenge.
     *
     * `challenge.id`, `codeHash`, and `tokenHash` are unique. Implementations
     * should enforce uniqueness on `tokenHash` at the storage layer; a
     * collision is astronomically unlikely but must fail loudly rather than
     * overwrite a live row.
     */
    insert(challenge: Challenge): Promise<void>;

    /**
     * Atomically claims a live challenge, returning it, or returns null.
     *
     * ## This method must be a single atomic compare-and-set
     *
     * This is the security-critical operation in the entire library. It must
     * be impossible for two concurrent callers to both receive a non-null
     * result for the same underlying challenge. A read-then-write
     * implementation — `SELECT`, check, `UPDATE` — has a race window between
     * the read and the write in which a second caller can also read the row
     * as unconsumed. Two clicks on the same link, two tabs, a client retry, or
     * an attacker replaying a captured token in parallel with the legitimate
     * user all reach that window in practice, and the result is a token that
     * authenticates twice.
     *
     * Express it as one guarded statement. In SQL:
     *
     * ```sql
     * UPDATE linkotp_challenge
     *    SET consumed_at = :now
     *  WHERE token_hash  = :tokenHash
     *    AND consumed_at IS NULL
     *    AND expires_at  > :now
     *    AND attempts    < max_attempts
     * RETURNING *
     * ```
     *
     * The `WHERE` clause is the guard and the `UPDATE` is the set; the
     * database performs both under one row lock. On engines without
     * `RETURNING`, branch on the affected-row count and read the row back
     * afterwards — the claim is still atomic because the guard lives in the
     * `UPDATE`.
     *
     * ## The guard must include every liveness condition
     *
     * Returning an expired, already-consumed, or attempt-exhausted challenge
     * defeats expiry, single-use, and brute-force limiting respectively. All
     * four predicates belong in the statement, not in calling code.
     *
     * @returns the claimed challenge with `consumedAt` set, or null if no live
     *          challenge matched. Callers cannot distinguish "wrong secret"
     *          from "expired" from "already used", by design.
     */
    consume(query: ConsumeQuery): Promise<Challenge | null>;

    /**
     * Increments the attempt counter for every live challenge on an address
     * and reports what is left.
     *
     * Called after a failed code submission. Because the submitted code was
     * wrong, the row cannot be located by `codeHash`, so the increment is
     * keyed by address and purpose. Under normal operation exactly one live
     * challenge exists per address.
     *
     * Once `attempts` reaches `maxAttempts` the `consume` guard can never
     * match again, which retires the challenge without a separate delete.
     *
     * `found` must report whether an unconsumed, unexpired challenge exists at
     * all, independently of whether this call was able to increment it. That
     * distinction is what separates "you have run out of attempts" from "there
     * is nothing here to attempt", which are different messages to a user and
     * are otherwise indistinguishable once the budget is spent.
     */
    registerFailedAttempt(query: {
        readonly email: string;
        readonly purpose: Purpose;
        readonly now: number;
    }): Promise<FailedAttemptOutcome>;

    /**
     * Removes a challenge outright.
     *
     * Used to roll back an issued challenge when the mailer throws, so a
     * failed send does not consume the caller's send quota or leave a live
     * secret nobody received.
     */
    delete(id: string): Promise<void>;

    /**
     * Counts challenges issued to an address since a timestamp, regardless of
     * whether they were later consumed or expired. Backs per-address send
     * throttling.
     */
    countIssuedSince(query: {
        readonly email: string;
        readonly purpose: Purpose;
        readonly since: number;
    }): Promise<number>;

    /**
     * Deletes rows that expired before `now`. Safe to call concurrently and
     * safe to never call — expiry is enforced by the `consume` guard, so this
     * is housekeeping for table size, not for correctness.
     *
     * @returns the number of rows removed.
     */
    deleteExpired(now: number): Promise<number>;
}

/** A rendered message, ready to hand to any transport. */
export interface MailerMessage {
    /** Normalized recipient address. */
    readonly to: string;
    readonly subject: string;
    /** Full HTML document. Self-contained: no external images, CSS, or fonts. */
    readonly html: string;
    /** Plain-text alternative. Never omit it — it drives deliverability. */
    readonly text: string;
    /**
     * Headers linkotp recommends setting. `Auto-Submitted` and
     * `X-Auto-Response-Suppress` stop out-of-office autoresponders from
     * bouncing sign-in mail back at you.
     */
    readonly headers: Readonly<Record<string, string>>;
}

/** Context passed alongside the message, for per-send routing or logging. */
export interface MailerContext {
    readonly purpose: Purpose;
    readonly metadata: Readonly<Record<string, unknown>> | null;
    /** Abort signal propagated from the originating request, when supplied. */
    readonly signal: AbortSignal | undefined;
}

/**
 * Transport hook. Throwing marks delivery failed and rolls back the
 * challenge, so throw on a hard failure and resolve on success.
 */
export type Mailer = (message: MailerMessage, context: MailerContext) => Promise<void>;

/** Verdict returned by a {@link RateLimiter}. */
export interface RateLimitVerdict {
    readonly allowed: boolean;
    /** Seconds until the caller may retry. Surfaced as `Retry-After`. */
    readonly retryAfter?: number;
}

/**
 * Throttling hook. linkotp calls this before issuing a challenge and before
 * verifying one, with a namespaced key. Bring your own — a Redis token
 * bucket, Cloudflare's rate limiting binding, an IP reputation service — or
 * use the bundled in-memory limiter for single-instance deployments.
 */
export interface RateLimiter {
    check(key: string, now: number): Promise<RateLimitVerdict>;
}

/** Successful outcome of {@link LinkOtp.start}. */
export interface StartResult {
    /**
     * Always true on a non-throwing return, including when `shouldSend`
     * suppressed delivery. Callers must not branch on this to decide what to
     * tell the user — see the enumeration note on `shouldSend`.
     */
    readonly sent: true;
    /** Epoch milliseconds at which the issued challenge stops being valid. */
    readonly expiresAt: number;
    /** Length of the code the user will be typing, for input sizing. */
    readonly codeLength: number;
}

/** Successful outcome of {@link LinkOtp.verifyCode} or {@link LinkOtp.verifyToken}. */
export interface VerifiedIdentity {
    readonly email: string;
    readonly purpose: Purpose;
    readonly metadata: Readonly<Record<string, unknown>> | null;
    /** Which arm of the challenge was used. Useful for analytics. */
    readonly via: "code" | "link";
    /** Epoch milliseconds. */
    readonly verifiedAt: number;
    /** Id of the consumed challenge, for audit logging. */
    readonly challengeId: string;
}
