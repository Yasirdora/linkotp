/**
 * The client half of the Better Auth plugin.
 *
 * ```ts
 * import { createAuthClient } from "better-auth/client";
 * import { otplinkClient } from "otplink/better-auth/client";
 *
 * export const authClient = createAuthClient({ plugins: [otplinkClient()] });
 *
 * await authClient.signIn.otplink({ email });
 * await authClient.signIn.otplink.code({ email, code });
 * ```
 *
 * Better Auth derives the client methods, their argument types, and their
 * return types from the server plugin's `endpoints` via `$InferServerPlugin`,
 * so there is nothing to keep in sync by hand — adding an endpoint on the
 * server adds a typed method here.
 *
 * The import of the server plugin is **type-only**, and deliberately so: a
 * value import would pull `plugin.ts`, and through it `better-auth/api` and
 * otplink's whole protocol core, into the browser bundle. The error codes are
 * the one runtime value this module needs, and they live in their own
 * dependency-free module for exactly that reason.
 */

import { OTPLINK_ERROR_CODES } from "./error-codes.ts";
import type { otplink } from "./plugin.ts";

export function otplinkClient() {
    return {
        id: "otplink",
        $InferServerPlugin: {} as ReturnType<typeof otplink>,

        /**
         * Refreshes the session atom after either arm redeems, so components
         * subscribed to the session re-render on sign-in instead of showing a
         * signed-out UI until the next navigation.
         *
         * The `GET` confirmation page is not listed. It redeems nothing, so
         * there is no new session to observe — signalling there would trigger
         * a pointless refetch on every scanner fetch and every page load.
         */
        atomListeners: [
            {
                matcher: (path: string) =>
                    path === "/sign-in/otplink/code" || path === "/otplink/verify",
                signal: "$sessionSignal",
            },
        ],

        $ERROR_CODES: OTPLINK_ERROR_CODES,
    } as const;
}
