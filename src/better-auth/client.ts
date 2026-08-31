/**
 * The client half of the Better Auth plugin.
 *
 * ```ts
 * import { createAuthClient } from "better-auth/client";
 * import { linkotpClient } from "linkotp/better-auth/client";
 *
 * export const authClient = createAuthClient({ plugins: [linkotpClient()] });
 *
 * await authClient.signIn.linkotp({ email });
 * await authClient.signIn.linkotp.code({ email, code });
 * ```
 *
 * Better Auth derives the client methods, their argument types, and their
 * return types from the server plugin's `endpoints` via `$InferServerPlugin`,
 * so there is nothing to keep in sync by hand — adding an endpoint on the
 * server adds a typed method here.
 *
 * The import of the server plugin is **type-only**, and deliberately so: a
 * value import would pull `plugin.ts`, and through it `better-auth/api` and
 * linkotp's whole protocol core, into the browser bundle. The error codes are
 * the one runtime value this module needs, and they live in their own
 * dependency-free module for exactly that reason.
 */

import { LINKOTP_ERROR_CODES } from "./error-codes.ts";
import type { linkotp } from "./plugin.ts";

export function linkotpClient() {
    return {
        id: "linkotp",
        $InferServerPlugin: {} as ReturnType<typeof linkotp>,

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
                    path === "/sign-in/linkotp/code" || path === "/linkotp/verify",
                signal: "$sessionSignal",
            },
        ],

        $ERROR_CODES: LINKOTP_ERROR_CODES,
    } as const;
}
