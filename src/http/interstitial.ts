/**
 * The confirmation page.
 *
 * ## Why a magic link must not sign you in on GET
 *
 * Corporate mail security scans every URL in inbound mail before the
 * recipient sees it. Microsoft Defender Safe Links, Proofpoint URL Defense,
 * Mimecast, Barracuda, and a long tail of smaller filters all issue a GET
 * against every link they find. Consumer clients add their own fetches for
 * link previews, and browsers prefetch.
 *
 * If GET consumes the token, every one of those fetches burns a single-use
 * credential. The user then clicks a link that was valid moments earlier and
 * is told it has expired. Worse, the scanner's request *succeeds*: the server
 * mints a real session and returns it to a security appliance, which discards
 * it. The credential is spent, and a session cookie briefly existed somewhere
 * nobody intended.
 *
 * This is also plain HTTP semantics. RFC 9110 requires GET to be safe, and
 * consuming a one-time credential is about as unsafe as a request gets.
 *
 * So GET renders this page and touches nothing. Only the POST it submits
 * consumes the token. Automated fetchers issue GET and stop there.
 */

import { randomString } from "../crypto.ts";

export interface InterstitialContext {
    /** The token, to be replayed in the form POST. */
    readonly token: string;
    /** Where the form posts. */
    readonly action: string;
    /** Product name for display. */
    readonly product: string;
    /**
     * "auto" submits on load, so a human sees a brief spinner and nothing
     * else. "manual" requires a click, which additionally defeats the small
     * minority of scanners that execute JavaScript, at the cost of one extra
     * interaction.
     */
    readonly mode: "auto" | "manual";
    /** CSP nonce authorizing the inline script. */
    readonly nonce: string;
}

const ESCAPES: Record<string, string> = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
};

function escapeHtml(value: string): string {
    return value.replace(/[&<>"']/g, (char) => ESCAPES[char]!);
}

/** Fresh nonce per response. A reused nonce is no better than 'unsafe-inline'. */
export function createNonce(): string {
    return randomString(22, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
}

/**
 * Response headers for anything that handles a token.
 *
 * `no-store` keeps the page out of shared caches and the browser's back/
 * forward cache. `no-referrer` stops the token in the address bar leaking
 * through the Referer header. `noindex` keeps a pasted link out of search
 * results. The CSP denies everything by default and permits only the inline
 * script carrying our nonce, so an injected tag cannot exfiltrate the token.
 */
export function securityHeaders(nonce: string): Record<string, string> {
    return {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
        Pragma: "no-cache",
        "Referrer-Policy": "no-referrer",
        "X-Robots-Tag": "noindex, nofollow",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": [
            "default-src 'none'",
            `script-src 'nonce-${nonce}'`,
            "style-src 'unsafe-inline'",
            "form-action 'self'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
        ].join("; "),
    };
}

export function renderInterstitial(context: InterstitialContext): string {
    const token = escapeHtml(context.token);
    const action = escapeHtml(context.action);
    const product = escapeHtml(context.product);
    const nonce = escapeHtml(context.nonce);
    const auto = context.mode === "auto";

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="light dark">
<title>Signing in to ${product}</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f6f6f7; --card: #ffffff; --line: #e6e6e9;
    --text: #111113; --muted: #6b6b74; --accent: #111113; --on-accent: #ffffff;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0b0b0c; --card: #17171a; --line: #2a2a30;
      --text: #ededf0; --muted: #9b9ba3; --accent: #ededf0; --on-accent: #0b0b0c;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center;
    justify-content: center; padding: 24px; background: var(--bg); color: var(--text);
    font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  .card {
    width: 100%; max-width: 380px; background: var(--card);
    border: 1px solid var(--line); border-radius: 14px; padding: 32px; text-align: center;
  }
  h1 { margin: 0 0 8px; font-size: 17px; font-weight: 600; }
  p { margin: 0; color: var(--muted); font-size: 14px; }
  button {
    margin-top: 22px; width: 100%; padding: 12px 20px; font: inherit; font-weight: 500;
    color: var(--on-accent); background: var(--accent); border: 0; border-radius: 9px;
    cursor: pointer;
  }
  button:hover { opacity: .9; }
  .spinner {
    margin: 22px auto 0; width: 22px; height: 22px; border-radius: 50%;
    border: 2px solid var(--line); border-top-color: var(--muted);
    animation: spin .7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .spinner { animation: none; } }
  .hidden { display: none; }
</style>
</head>
<body>
  <main class="card">
    <h1>${auto ? "Signing you in" : "Confirm sign-in"}</h1>
    <p>${
        auto
            ? `One moment while we finish signing you in to ${product}.`
            : `Continue to finish signing in to ${product}.`
    }</p>

    <form id="f" method="POST" action="${action}">
      <input type="hidden" name="token" value="${token}">
      <button type="submit"${auto ? ' class="hidden" id="b"' : ""}>Continue</button>
    </form>

    ${auto ? '<div class="spinner" id="s"></div>' : ""}

    <noscript>
      <p style="margin-top:18px">JavaScript is off. Use the Continue button above.</p>
    </noscript>
  </main>

<script nonce="${nonce}">
(function () {
  // Remove the token from the address bar so it does not linger in browser
  // history, screen shares, or a screenshot. The form already holds it.
  try {
    history.replaceState(null, "", location.pathname);
  } catch (e) {}
${
    auto
        ? `
  // Reveal the manual button immediately, so a failed auto-submit still
  // leaves a usable page rather than a spinner that never resolves.
  var b = document.getElementById("b");
  var s = document.getElementById("s");
  setTimeout(function () {
    if (b) b.className = "";
    if (s) s.className = "hidden";
  }, 4000);

  document.getElementById("f").submit();`
        : ""
}
})();
</script>
</body>
</html>`;
}
