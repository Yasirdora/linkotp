/**
 * Error taxonomy.
 *
 * Every failure path in linkotp throws an `LinkOtpError` carrying a stable
 * machine-readable `code`. Callers switch on the code; the `message` is for
 * logs, never for users.
 *
 * `publicMessage` is the only string safe to show an end user. It is
 * deliberately vague for anything that could distinguish "this address has a
 * pending challenge" from "it doesn't" — see `docs/security.md` on
 * enumeration.
 */

export type LinkOtpErrorCode =
    /** The supplied address failed syntactic validation. */
    | "invalid_email"
    /** A rate limiter rejected the request. Check `retryAfter`. */
    | "rate_limited"
    /** No live challenge matched. Covers expired, consumed, and never-existed. */
    | "invalid_challenge"
    /** The submitted code did not match a live challenge. */
    | "invalid_code"
    /** The challenge burned through `maxAttempts` and is permanently dead. */
    | "too_many_attempts"
    /** The link token did not match a live challenge. */
    | "invalid_token"
    /** Device binding was required and the presented binding did not match. */
    | "binding_mismatch"
    /** The mailer threw. The challenge is rolled back where possible. */
    | "delivery_failed"
    /** Programmer error: bad config passed to `createLinkOtp`. */
    | "configuration_error";

const PUBLIC_MESSAGES: Record<LinkOtpErrorCode, string> = {
    invalid_email: "Enter a valid email address.",
    rate_limited: "Too many attempts. Please wait a moment and try again.",
    invalid_challenge: "That sign-in request is no longer valid. Request a new one.",
    invalid_code: "That code is incorrect or has expired.",
    too_many_attempts: "Too many incorrect attempts. Request a new code.",
    invalid_token: "That link is no longer valid. Request a new one.",
    binding_mismatch: "Open the link in the same browser you started from.",
    delivery_failed: "We couldn't send that email. Please try again.",
    configuration_error: "Something went wrong on our end.",
};

const STATUS: Record<LinkOtpErrorCode, number> = {
    invalid_email: 400,
    rate_limited: 429,
    invalid_challenge: 400,
    invalid_code: 400,
    too_many_attempts: 429,
    invalid_token: 400,
    binding_mismatch: 400,
    delivery_failed: 502,
    configuration_error: 500,
};

export interface LinkOtpErrorOptions {
    /** Seconds the caller should wait before retrying. Only for `rate_limited`. */
    retryAfter?: number;
    /** Attempts left on the challenge. Only for `invalid_code`. */
    remainingAttempts?: number;
    /** Underlying error, preserved for logs. */
    cause?: unknown;
}

export class LinkOtpError extends Error {
    readonly code: LinkOtpErrorCode;
    /** Suggested HTTP status. The bundled handler uses this. */
    readonly status: number;
    /** Safe to render to an end user. */
    readonly publicMessage: string;
    readonly retryAfter?: number;
    readonly remainingAttempts?: number;

    constructor(code: LinkOtpErrorCode, message?: string, options: LinkOtpErrorOptions = {}) {
        super(message ?? code, options.cause !== undefined ? { cause: options.cause } : undefined);
        this.name = "LinkOtpError";
        this.code = code;
        this.status = STATUS[code];
        this.publicMessage = PUBLIC_MESSAGES[code];
        if (options.retryAfter !== undefined) this.retryAfter = options.retryAfter;
        if (options.remainingAttempts !== undefined) {
            this.remainingAttempts = options.remainingAttempts;
        }
    }

    /** Narrowing helper that survives bundling and duplicated module instances. */
    static is(value: unknown): value is LinkOtpError {
        return value instanceof Error && value.name === "LinkOtpError" && "code" in value;
    }

    /** Shape suitable for a JSON error response. Never includes `message`. */
    toJSON(): { error: LinkOtpErrorCode; message: string; retryAfter?: number } {
        return {
            error: this.code,
            message: this.publicMessage,
            ...(this.retryAfter !== undefined ? { retryAfter: this.retryAfter } : {}),
        };
    }
}
