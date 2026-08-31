/**
 * linkotp for Better Auth.
 *
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { linkotp } from "linkotp/better-auth";
 *
 * export const auth = betterAuth({
 *     database: db,
 *     plugins: [
 *         linkotp({
 *             secret: process.env.LINKOTP_SECRET!,
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

export { linkotp } from "./plugin.ts";
export type { OtplinkPluginOptions } from "./plugin.ts";

export { LINKOTP_ERROR_CODES } from "./error-codes.ts";
export type { OtplinkErrorCode } from "./error-codes.ts";

export { createBetterAuthStore, DEFAULT_MODEL } from "./store.ts";
export type {
    AdapterWhere,
    BetterAuthAdapterLike,
    BetterAuthStoreOptions,
} from "./store.ts";

export { linkotpSchema } from "./schema.ts";
export type { PluginSchema, SchemaOptions } from "./schema.ts";
