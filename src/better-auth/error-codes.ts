/**
 * The plugin's error codes, in the shape Better Auth's `$ERROR_CODES` expects.
 *
 * Better Auth ships `defineErrorCodes` for exactly this, but it lives in
 * `@better-auth/core/utils/error-codes` and is not re-exported from
 * `better-auth`. Reaching into a transitive dependency is fragile under
 * strict installers, which hoist nothing they were not asked to, so the
 * five-line shape is reproduced here instead. It is a data format, not
 * behaviour, and copying it keeps the peer surface to the one package the
 * user actually installed.
 *
 * Kept in its own module, importing nothing, so the client plugin can carry
 * these codes to the browser without dragging the server plugin — and through
 * it `better-auth/api` — into the bundle.
 */

/** Mirrors Better Auth's `RawError`. */
export interface OtplinkErrorCode<K extends string = string> {
    readonly code: K;
    readonly message: string;
}

type Defined<T extends Record<string, string>> = {
    readonly [K in keyof T & string]: OtplinkErrorCode<K>;
};

/**
 * Keys must be UPPER_SNAKE_CASE: Better Auth validates that at the type level
 * and rejects anything else.
 */
function define<const T extends Record<string, string>>(codes: T): Defined<T> {
    return Object.fromEntries(
        Object.entries(codes).map(([code, message]) => [
            code,
            // `toString` returning the key is what lets a code be compared
            // against, and interpolated as, its own name.
            { code, message, toString: () => code },
        ]),
    ) as Defined<T>;
}

export const OTPLINK_ERROR_CODES = define({
    OTPLINK_INVALID_EMAIL: "Enter a valid email address.",
    OTPLINK_RATE_LIMITED: "Too many attempts. Please wait a moment and try again.",
    OTPLINK_INVALID_CODE: "That code is incorrect or has expired.",
    OTPLINK_TOO_MANY_ATTEMPTS: "Too many incorrect attempts. Request a new code.",
    OTPLINK_INVALID_TOKEN: "That link is no longer valid. Request a new one.",
    OTPLINK_BINDING_MISMATCH: "Open the link in the same browser you started from.",
    OTPLINK_DELIVERY_FAILED: "We couldn't send that email. Please try again.",
    OTPLINK_SIGNUP_DISABLED: "That address does not have an account.",
});
