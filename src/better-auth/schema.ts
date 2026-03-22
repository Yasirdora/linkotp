/**
 * The table Better Auth will create and migrate for otplink.
 *
 * Declared in Better Auth's plugin schema format, so `better-auth generate`
 * and `better-auth migrate` produce the columns and indexes without the user
 * hand-writing a migration.
 *
 * Field names are the *model* field names. Better Auth maps them to column
 * names per adapter convention, so nothing here assumes snake_case or
 * camelCase in the database.
 */

import type { BetterAuthPlugin } from "better-auth/types";

import { DEFAULT_MODEL } from "./store.ts";

/**
 * Derived from Better Auth's own plugin type rather than restated.
 *
 * A hand-written approximation looks harmless and is not: field attributes
 * typed as `Record<string, unknown>` are not assignable to `DBFieldAttribute`,
 * which quietly makes the whole plugin fail to satisfy `BetterAuthPlugin` —
 * the schema is the only structurally-checked part of it. Deriving keeps this
 * exact by construction, and costs nothing, since this entry point already
 * requires `better-auth`.
 *
 * `BetterAuthPluginDBSchema` is not re-exported from `better-auth` itself, so
 * it is reached through the plugin type, which is.
 */
export type PluginSchema = NonNullable<BetterAuthPlugin["schema"]>;

export interface SchemaOptions {
    /** @default "otplinkChallenge" */
    readonly model?: string;
    /** Physical table name, when it should differ from the model name. */
    readonly modelName?: string;
    /** Skip migration generation, e.g. when the table is managed elsewhere. */
    readonly disableMigration?: boolean;
}

export function otplinkSchema(options: SchemaOptions = {}): PluginSchema {
    const model = options.model ?? DEFAULT_MODEL;

    return {
        [model]: {
            ...(options.modelName !== undefined ? { modelName: options.modelName } : {}),
            ...(options.disableMigration !== undefined
                ? { disableMigration: options.disableMigration }
                : {}),
            fields: {
                /**
                 * otplink's own challenge id, distinct from Better Auth's
                 * primary key. Better Auth generates `id` itself and several
                 * adapters require that, so the protocol's identifier lives
                 * in its own unique, indexed column.
                 */
                challengeId: { type: "string", required: true, unique: true, index: true },
                email: { type: "string", required: true, index: true },
                purpose: { type: "string", required: true },
                /**
                 * Keyed HMAC digests, never plaintext and never a plain salted
                 * hash. The key is the application secret and lives in the
                 * environment, so these columns are inert to anyone who
                 * obtains the database alone.
                 */
                codeHash: { type: "string", required: true, index: true },
                /**
                 * Unique is not decorative. At 286 bits a token collision will
                 * not happen, but a misconfigured `token.length` could shrink
                 * that, and the constraint turns a silent authentication bug
                 * into a loud insert failure.
                 */
                tokenHash: { type: "string", required: true, unique: true, index: true },
                bindingHash: { type: "string", required: false },
                /** JSON-encoded. `json` is the least uniform column type across adapters. */
                metadata: { type: "string", required: false },
                /**
                 * Counts *down*. Better Auth's `Where` compares a field to a
                 * literal and never to another field, so `attempts <
                 * maxAttempts` is inexpressible; `attemptsRemaining > 0` says
                 * the same thing against a literal. See `store.ts`.
                 */
                attemptsRemaining: { type: "number", required: true },
                maxAttempts: { type: "number", required: true },
                createdAt: { type: "date", required: true },
                expiresAt: { type: "date", required: true, index: true },
                /** Null while live. Set once, by the guarded update that claims it. */
                consumedAt: { type: "date", required: false },
            },
        },
    };
}
