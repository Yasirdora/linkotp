/**
 * otplink — one email, two ways in.
 *
 * A passwordless auth primitive that issues a typed code and a scanner-safe
 * magic link as a single challenge, delivered in one message. Zero runtime
 * dependencies, Web Standard APIs only, and no opinion about your framework,
 * database, mail transport, or session library.
 *
 * @packageDocumentation
 */

export { createOtpLink } from "./core.ts";
export type {
    OtpLink,
    PublicConfig,
    StartInput,
    VerifyCodeInput,
    VerifyTokenInput,
} from "./core.ts";

export {
    DEFAULT_CODE_ALPHABET,
    DEFAULT_CODE_LENGTH,
    DEFAULT_TOKEN_ALPHABET,
    DEFAULT_TOKEN_LENGTH,
    normalizeCode,
    normalizeEmail,
} from "./config.ts";
export type {
    BindingOptions,
    EmailOptions,
    OtpLinkOptions,
    RenderContext,
    SecretRotation,
    SecretShape,
} from "./config.ts";

export { OtpLinkError } from "./errors.ts";
export type { OtpLinkErrorCode, OtpLinkErrorOptions } from "./errors.ts";

export { renderDefaultTemplate, RECOMMENDED_HEADERS } from "./email.ts";

export { createMemoryRateLimiter } from "./ratelimit.ts";
export type { MemoryRateLimiterOptions } from "./ratelimit.ts";

export { entropyBits, randomString, timingSafeEqual } from "./crypto.ts";

export type {
    Challenge,
    ConsumeQuery,
    Mailer,
    MailerContext,
    MailerMessage,
    Purpose,
    RateLimiter,
    RateLimitVerdict,
    StartResult,
    TokenStore,
    VerifiedIdentity,
} from "./types.ts";
