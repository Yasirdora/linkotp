/**
 * HTTP adapter built on the Fetch API.
 *
 * Optional. The core exposes `start`, `verifyCode`, and `verifyToken`
 * directly, so wiring your own routes is entirely reasonable, but the
 * scanner-safe GET/POST split and the security headers are easy to get subtly
 * wrong and are provided here already correct.
 */

export { createHandler, sanitizeRedirect } from "./handler.ts";
export type { HandlerOptions, VerifiedResponse } from "./handler.ts";

export { createNonce, renderInterstitial, securityHeaders } from "./interstitial.ts";
export type { InterstitialContext } from "./interstitial.ts";
