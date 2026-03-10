/**
 * Default message template.
 *
 * Constraints that shaped this markup:
 *
 *   - Table layout and inline styles, because Outlook's rendering engine is
 *     Microsoft Word and it does not implement flexbox, grid, or most of CSS.
 *   - No external images, fonts, or stylesheets. Remote assets are blocked by
 *     default in most clients, and a tracking pixel in a sign-in email is a
 *     privacy liability nobody asked for.
 *   - A real plain-text alternative. Sending HTML alone is one of the
 *     strongest spam signals there is, and sign-in mail must not land in junk.
 *   - The code unspaced in that plain-text part. iOS and Android scan it to
 *     offer one-tap autofill, and their heuristics look for an unbroken
 *     token near a word like "code". The HTML part gets its visual spacing
 *     from CSS letter-spacing, which does not alter the underlying text.
 *   - Dark mode via prefers-color-scheme, with colors that stay legible when a
 *     client force-inverts anyway.
 */

import type { RenderContext } from "./config.ts";

const ESCAPES: Record<string, string> = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
};

/**
 * Escapes text for interpolation into HTML.
 *
 * Applied to every dynamic value without exception, including ones that
 * "cannot" contain markup. The product name comes from configuration, the
 * code from our own alphabet, and the URL from our own builder, but a
 * template that escapes only the values it currently believes are risky
 * becomes an injection the first time someone adds a field.
 */
function escapeHtml(value: string): string {
    return value.replace(/[&<>"']/g, (char) => ESCAPES[char]!);
}

export function renderDefaultTemplate(context: RenderContext): { html: string; text: string } {
    const product = escapeHtml(context.product);
    const code = escapeHtml(context.code);
    const url = escapeHtml(context.url);
    const minutes = String(context.ttlMinutes);

    const text = [
        `Your sign-in code for ${context.product}`,
        "",
        `    ${context.code}`,
        "",
        `Enter that code in the app, or open this link to sign in:`,
        "",
        context.url,
        "",
        `The code and the link both expire in ${minutes} minutes, and either one`,
        `can be used only once.`,
        "",
        `If you did not request this, you can ignore this email. Someone may have`,
        `typed your address by mistake. No account was created or changed.`,
    ].join("\n");

    const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<meta name="referrer" content="no-referrer">
<title>Your sign-in code for ${product}</title>
<style>
  :root { color-scheme: light dark; }
  @media (prefers-color-scheme: dark) {
    .ol-bg   { background: #0b0b0c !important; }
    .ol-card { background: #17171a !important; border-color: #2a2a30 !important; }
    .ol-text { color: #ededf0 !important; }
    .ol-muted{ color: #9b9ba3 !important; }
    .ol-code { background: #0b0b0c !important; color: #ededf0 !important; border-color: #2a2a30 !important; }
    .ol-btn  { background: #ededf0 !important; }
    .ol-btn a{ color: #0b0b0c !important; }
    .ol-rule { border-color: #2a2a30 !important; }
  }
</style>
</head>
<body class="ol-bg" style="margin:0;padding:0;background:#f6f6f7;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">Your code is ${code}. It expires in ${minutes} minutes.</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="ol-bg" style="background:#f6f6f7;">
  <tr>
    <td align="center" style="padding:40px 16px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="ol-card" style="max-width:440px;background:#ffffff;border:1px solid #e6e6e9;border-radius:14px;">
        <tr>
          <td style="padding:36px 32px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">

            <h1 class="ol-text" style="margin:0 0 8px;font-size:19px;line-height:1.35;font-weight:600;color:#111113;">
              Your sign-in code
            </h1>
            <p class="ol-muted" style="margin:0 0 26px;font-size:14px;line-height:1.6;color:#6b6b74;">
              Enter this code in ${product}, or use the button below.
            </p>

            <div class="ol-code" style="background:#fafafa;border:1px solid #e6e6e9;border-radius:10px;padding:18px 12px;text-align:center;font-family:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,monospace;font-size:29px;font-weight:600;letter-spacing:0.22em;color:#111113;">
              ${code}
            </div>

            <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:26px 0 0;">
              <tr>
                <td class="ol-btn" style="border-radius:9px;background:#111113;">
                  <a href="${url}" style="display:inline-block;padding:13px 26px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:14px;font-weight:500;line-height:1;color:#ffffff;text-decoration:none;border-radius:9px;">
                    Sign in to ${product}
                  </a>
                </td>
              </tr>
            </table>

            <p class="ol-muted" style="margin:26px 0 0;font-size:13px;line-height:1.6;color:#6b6b74;">
              The code and the link both expire in ${minutes} minutes and can each be used once.
            </p>

            <div class="ol-rule" style="margin:26px 0 0;padding:20px 0 0;border-top:1px solid #eeeef0;">
              <p class="ol-muted" style="margin:0;font-size:12px;line-height:1.6;color:#9b9ba3;">
                If you did not request this, you can ignore this email. Someone may have typed your address by mistake, and nothing has been created or changed.
              </p>
            </div>

          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
</body>
</html>`;

    return { html, text };
}

/**
 * Headers worth setting on every sign-in message.
 *
 * `Auto-Submitted` and `X-Auto-Response-Suppress` stop out-of-office
 * autoresponders from replying to sign-in mail, which otherwise produces a
 * steady trickle of bounces against the sending reputation that delivers
 * these messages in the first place.
 */
export const RECOMMENDED_HEADERS: Readonly<Record<string, string>> = Object.freeze({
    "Auto-Submitted": "auto-generated",
    "X-Auto-Response-Suppress": "All",
    "X-Entity-Ref-ID": "otplink",
});
