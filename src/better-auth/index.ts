/**
 * otplink for Better Auth.
 *
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { otplink } from "otplink/better-auth";
 *
 * export const auth = betterAuth({
 *     database: db,
 *     plugins: [
 *         otplink({
 *             secret: process.env.OTPLINK_SECRET!,
 *             baseUrl: "https://example.com",
 *             mailer: async (message) => { await send(message); },
 *         }),
 *     ],
 * });
 * ```
 *
 * Then run `better-auth generate` to create the challenge table.
 *
 * `better-auth` is an *optional* peer dependency: it is imported only by this
 * entry point, so the rest of the package installs and runs with nothing at
 * all in `dependencies`.
 */

export { otplink, OTPLINK_ERROR_CODES } from "./plugin.ts";
export type { OtplinkPluginOptions } from "./plugin.ts";

export { createBetterAuthStore, DEFAULT_MODEL } from "./store.ts";
export type {
    AdapterWhere,
    BetterAuthAdapterLike,
    BetterAuthStoreOptions,
} from "./store.ts";

export { otplinkSchema } from "./schema.ts";
export type { PluginSchema, SchemaOptions } from "./schema.ts";
