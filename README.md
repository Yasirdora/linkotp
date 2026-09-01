# linkotp

[![CI](https://github.com/Yasirdora/linkotp/actions/workflows/ci.yml/badge.svg)](https://github.com/Yasirdora/linkotp/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/linkotp.svg?style=flat)](https://www.npmjs.com/package/linkotp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)


**A zero-dependency passwordless auth primitive** delivering a typed code and scanner-safe magic link in one email.

- **Zero runtime dependencies.** Web Standard APIs only. (`linkotp/better-auth` declares Better Auth as an *optional* peer, so it installs nothing unless you import it.)
- **Runs anywhere.** Node, Bun, Deno, Cloudflare Workers, Vercel Edge.
- **No framework opinion.** Next.js, SvelteKit, Remix, Astro, Hono, Express, or your own routes.
- **No database opinion.** Postgres, SQLite, D1, Turso, MySQL, or six methods of your own.
- **Does not mint sessions.** It proves an address; your session library does the rest.

```bash
npm install @yasirdora/linkotp
```

---

## Why this exists

Sending a code and a link in one email is a well-worn pattern — Slack, Notion, Linear, and Vercel all do it. Implementing it on top of an existing OTP plugin is where it goes wrong, in two specific ways.

### 1. The link must not carry the code

The tempting shortcut is to put the OTP in the URL, either plainly or "hidden" in base64:

```
https://example.com/auth/verify?code=418207&email=you@example.com   ❌
https://example.com/auth/verify?payload=eyJjb2RlIjoiNDE4MjA3In0=    ❌
```

*(Note: Base64 is an encoding, not encryption. Anyone who intercepts the second link can trivially decode it to find the code).*

Now the link is only as strong as the code. Six digits is about **20 bits** — perfectly safe for a value typed into a rate-limited form, and far too weak for a bearer credential that lands in browser history, server access logs, CDN logs, and `Referer` headers. Those are two different threat models, and one secret cannot serve both.

linkotp issues **two independent secrets** bound to one challenge:

| | Entropy | Where it travels |
|---|---:|---|
| Code — 6 chars over a 32-char alphabet | **~30 bits** | Typed into a form |
| Token — 48 chars over a 62-char alphabet | **~286 bits** | Carried in a URL |

Redeeming either one retires the other. Both are stored as HMAC digests keyed by a secret that lives outside the database.

### 2. A magic link must not be consumed by `GET`

Microsoft Defender Safe Links, Proofpoint, Mimecast, and Barracuda fetch every URL in inbound mail before the recipient sees it. Consumer clients add link previews; browsers prefetch.

If `GET` consumes the token, each of those fetches burns a single-use credential. The user clicks a link that was valid seconds ago and is told it expired. Worse, the scanner's request *succeeds* — the server mints a real session and hands it to a security appliance, which throws it away.

This is also plain HTTP: [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110#name-safe-methods) requires `GET` to be safe, and spending a one-time credential is not.

linkotp's `GET` renders a confirmation page and touches nothing. Only the `POST` that page submits consumes the token. Automated fetchers issue `GET` and stop.

---

## Quick start

```ts
import { createLinkOtp } from "@yasirdora/linkotp";
import { createSqlStore, schemaFor } from \"@yasirdora/linkotp/stores\";

const auth = createLinkOtp({
  secret: process.env.LINKOTP_SECRET!,   // 32+ chars, from the environment
  baseUrl: "https://example.com",
  store: createSqlStore({ driver, dialect: "postgres" }),
  mailer: async (message) => {
    await resend.emails.send({
      from: "Example <auth@example.com>",
      to: message.to,
      subject: message.subject,
      html: message.html,
      text: message.text,
      headers: message.headers,
    });
  },
});
```

Create the table once with `schemaFor("postgres")`, then:

```ts
await auth.start({ email: "person@example.com" });

// The user types the code…
const identity = await auth.verifyCode({ email, code });

// …or clicks the link.
const identity = await auth.verifyToken({ token });

identity; // { email, purpose, metadata, via: "code" | "link", verifiedAt, challengeId }
```

Generate a secret:

```bash
node -e "console.log(crypto.randomBytes(32).toString('base64url'))"
```

---

## The HTTP layer

`createHandler` returns one `(Request) => Promise<Response>` built on the Fetch API, with the `GET`/`POST` split, the CSP nonce, and the security headers already correct.

```ts
import { createHandler } from \"@yasirdora/linkotp/http\";

export const handler = createHandler(auth, {
  async onVerified(identity, request) {
    // linkotp does not create sessions. This is where you do.
    const cookie = await mySessionLibrary.create(identity.email);
    return { headers: { "Set-Cookie": cookie }, redirectTo: "/dashboard" };
  },
});
```

It serves four routes:

| Route | Method | What it does |
|---|---|---|
| `/api/auth/start` | `POST` | Issues and sends a challenge |
| `/api/auth/verify` | `POST` | Redeems a typed code |
| `/auth/verify` | `GET` | Renders the confirmation page — **consumes nothing** |
| `/auth/verify` | `POST` | Redeems the link token |

Both paths are configurable (`basePath`, and `verifyPath` on the instance).

### Framework recipes

<details open>
<summary><b>Next.js</b> (App Router)</summary>

```ts
// app/api/auth/[...route]/route.ts
export const POST = handler;

// app/auth/verify/route.ts
export const GET = handler;
export const POST = handler;
```
</details>

<details>
<summary><b>SvelteKit</b></summary>

```ts
// src/routes/[...route]/+server.ts
export const GET = ({ request }) => handler(request);
export const POST = ({ request }) => handler(request);
```
</details>

<details>
<summary><b>Hono, Elysia, Nitro</b></summary>

```ts
app.all("/api/auth/*", (c) => handler(c.req.raw));
app.all("/auth/verify", (c) => handler(c.req.raw));
```
</details>

<details>
<summary><b>Cloudflare Workers, Deno, Bun</b></summary>

```ts
export default { fetch: handler };            // Workers
Deno.serve(handler);                          // Deno
Bun.serve({ fetch: handler });                // Bun
```
</details>

<details>
<summary><b>Astro</b></summary>

```ts
// src/pages/api/auth/[...route].ts
export const ALL = ({ request }) => handler(request);
```
</details>

<details>
<summary><b>Express</b> (needs a small shim)</summary>

Express predates the Fetch API, so convert at the boundary:

```ts
import { Readable } from "node:stream";

app.use(async (req, res, next) => {
  const url = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
  const request = new Request(url, {
    method: req.method,
    headers: req.headers as Record<string, string>,
    body: ["GET", "HEAD"].includes(req.method) ? undefined : req,
    duplex: "half",
  });

  const response = await handler(request);
  if (response.status === 404) return next();

  res.status(response.status);
  for (const [k, v] of response.headers) res.append(k, v);
  if (response.body) Readable.fromWeb(response.body).pipe(res);
  else res.end();
});
```
</details>

Or skip the handler entirely and call `start` / `verifyCode` / `verifyToken` from your own routes. The core has no HTTP dependency.

---

## Stores

```ts
import { createMemoryStore, createSqlStore, schemaFor } from \"@yasirdora/linkotp/stores\";
```

`createSqlStore` needs a two-method driver, so any client works:

```ts
// Cloudflare D1
const driver = {
  all: (sql, params) => env.DB.prepare(sql).bind(...params).all().then((r) => r.results),
  run: (sql, params) =>
    env.DB.prepare(sql).bind(...params).run().then((r) => ({ rowsAffected: r.meta.changes })),
};

// node:postgres, postgres.js, better-sqlite3, libSQL — same shape.
```

Dialects: `sqlite` (default), `postgres`, `mysql`. SQLite and Postgres use `RETURNING`; MySQL takes an equivalent two-statement path that is still atomic.

### Writing your own

The interface is six methods, and one of them carries the entire security model. `consume` **must be a single guarded compare-and-set**:

```sql
UPDATE linkotp_challenge
   SET consumed_at = :now
 WHERE token_hash  = :tokenHash
   AND consumed_at IS NULL
   AND expires_at  > :now
   AND attempts    < max_attempts
RETURNING *
```

A read-then-write implementation has a window in which two callers both see the row as unconsumed, and a single-use token authenticates twice. The compiler cannot catch that, so there is a suite that can:

```ts
import { checkStoreConformance } from \"@yasirdora/linkotp/testing\";

const report = await checkStoreConformance({ createStore: () => myStore() });
assert.ok(report.passed, report.summary);
```

Seventeen checks, including firing 24 concurrent `consume` calls at one challenge and asserting exactly one wins. Run it in your own CI.

---

## Better Auth

```bash
npm install @yasirdora/linkotp better-auth
```

```ts
import { betterAuth } from "better-auth";
import { linkotp } from \"@yasirdora/linkotp/better-auth\";

export const auth = betterAuth({
  database: db,
  plugins: [
    linkotp({
      secret: process.env.LINKOTP_SECRET!,   // 32+ chars, from the environment
      baseUrl: "https://example.com",
      mailer: async (message) => { await send(message); },
    }),
  ],
});
```

Then `npx @better-auth/cli generate` to create the challenge table, and `migrate` to apply it.

On the client:

```ts
import { createAuthClient } from "better-auth/client";
import { linkotpClient } from \"@yasirdora/linkotp/better-auth/client\";

export const authClient = createAuthClient({ plugins: [linkotpClient()] });

await authClient.signIn.linkotp({ email });            // sends the email
await authClient.signIn.linkotp.code({ email, code }); // redeems the typed code
```

The link arm needs no client call — the user clicks it and lands back on your app with a session. Method names, argument types, and return types are all inferred from the server plugin, so there is nothing to keep in sync.

| Endpoint | Method | What it does |
|---|---|---|
| `/sign-in/linkotp` | `POST` | Issues one challenge and mails the code and the link |
| `/sign-in/linkotp/code` | `POST` | Redeems the typed code |
| `/linkotp/verify` | `GET` | Renders the confirmation page. **Consumes nothing.** |
| `/linkotp/verify` | `POST` | Redeems the link token |

The `GET`/`POST` split is the point. Better Auth's built-in `magicLink` redeems on `GET`, which is why [discussion #6985](https://github.com/better-auth/better-auth/discussions/6985) is open: Defender Safe Links, Proofpoint, Mimecast, and Barracuda fetch every URL in inbound mail, so the scanner spends the credential and the user is told their brand-new link expired. The usual workaround — raising `allowedAttempts` — turns a single-use credential into a multi-use one, which is a downgrade dressed as a fix. Here the scanner gets HTML and the token survives; and because the same email carries a code on a *separate* secret, a user whose link is mangled entirely still has a way in.

Sessions stay Better Auth's. linkotp verifies control of an address and hands off to `internalAdapter` and `setSessionCookie`.

A link that has expired, been redeemed, or been retired by too many wrong guesses is the ordinary end of a challenge's life, and the person clicking it is in a browser. Those all redirect to `errorCallbackURL` with `?error=<code>` rather than rendering a JSON error body:

```ts
linkotp({
  // ...
  defaultCallbackURL: "/dashboard",
  errorCallbackURL: "/sign-in",   // receives ?error=invalid_token
});
```

Expired rows are inert — the `consume` guard enforces expiry regardless — but they do accumulate. Better Auth has no scheduler, so call `sweep()` from your own cron if table size matters:

```ts
import { createBetterAuthStore } from \"@yasirdora/linkotp/better-auth\";

const { adapter } = await auth.$context;      // note: $context is a promise
await createBetterAuthStore({ adapter }).deleteExpired(Date.now());
```

**On the store.** The plugin persists challenges through Better Auth's own adapter, so there is no second database connection to configure. Its `Where` clause compares a field to a literal and never to another field, so `attempts < maxAttempts` cannot be expressed; the table stores `attemptsRemaining` and guards `attemptsRemaining > 0` instead. Same meaning, and the guard stays inside a single `updateMany`, which is what keeps `consume` an atomic compare-and-set.

The bundled conformance suite runs against it twice: once on the memory adapter, and once on real SQLite through Better Auth's Kysely adapter, with the table created by Better Auth's own migrator. The second run is what establishes that the guard actually compiles to one `UPDATE` and that a genuine row lock elects the winner — on the memory adapter that would be JavaScript's single thread doing the work.

> **Note.** Better Auth types `updateMany` as `Promise<number>`. Its first-party adapters honour that as of 1.7; through 1.6.2 the Drizzle adapter returned the raw driver result and the memory adapter returned the updated record. The store reads every documented driver shape and *throws* on one it cannot read, rather than reporting zero rows — an adapter incompatibility should not look like an expired link.

Requires `better-auth@>=1.7.0`, and this entry point is ESM-only, because Better Auth is.

**Not yet supported here:** device binding (`binding.enabled`), which needs a cookie this entry point does not yet set — the plugin refuses to start rather than ignore it, so nobody deploys believing they have it. `linkotp/http` implements it. The plugin also covers sign-in only; email verification and password reset are `purpose`s the core supports but the plugin does not expose.

---

## Security model

| Property | How |
|---|---|
| Secrets at rest | HMAC-SHA256 keyed by an application secret, domain-separated per use. A database leak alone reveals nothing. |
| Code binding | The code digest includes the address, so a captured digest cannot be replayed against another account. |
| Single use | Enforced by a guarded atomic `UPDATE`, not by application logic. |
| Brute force | Configurable attempt ceiling; the guard re-checks it on every claim. |
| Randomness | `crypto.getRandomValues` with rejection sampling. Naive `byte % 62` skews the first eight characters by ~25%. |
| Enumeration | `shouldSend` suppresses delivery while returning an identical result, padded to a latency floor. |
| Open redirect | Every redirect is restricted to a same-origin path. |
| Login CSRF | State-changing `POST`s are checked against `Sec-Fetch-Site` / `Origin`. |
| Token leakage | `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Robots-Tag: noindex`, and the token is stripped from the address bar on load. |
| XSS on the confirmation page | `default-src 'none'` with a fresh per-response nonce. |
| Config errors | Weak secrets, non-https origins, and under-entropy tokens are rejected at startup, not at 3am. |

Two things it deliberately does **not** do: create sessions, and rate-limit across instances. Both are yours, with hooks provided (`onVerified`, `RateLimiter`).

See [SECURITY.md](./SECURITY.md) for the full threat model and the residual risks.

---

## Configuration

```ts
createLinkOtp({
  secret,                       // required, 32+ chars
  baseUrl,                      // required, https outside localhost
  store, mailer,                // required

  verifyPath: "/auth/verify",
  ttlSeconds: 900,              // 60 … 86400
  maxAttempts: 5,

  code:  { length: 6,  alphabet: "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" },
  token: { length: 48, alphabet: "a-zA-Z0-9" },

  email: { product: "Acme", subject: ({ product }) => `Sign in to ${product}`, render },
  binding: { enabled: false },  // tie the link to the requesting browser
  rotation: { previous: [oldSecret] },
  maxSendsPerAddress: { count: 5, windowSeconds: 900 },
  rateLimiter,                  // any { check(key, now) }
  shouldSend: async (email) => await userExists(email),   // close sign-ups, no leak
  minimumStartDurationMs: 500,
});
```

**Closing sign-ups without leaking who has an account** is the common case for `shouldSend`:

```ts
shouldSend: async (email) => Boolean(await db.findUser(email)),
```

`start` returns the same result and takes the same time either way, so probing the endpoint reveals nothing.

**Rotating the secret** without invalidating live challenges:

```ts
{ secret: NEW, rotation: { previous: [OLD] } }   // drop OLD after one TTL
```

---

## Errors

Every failure throws an `LinkOtpError` with a stable `code`, a suggested `status`, and a `publicMessage` that is safe to show a user.

```ts
import { LinkOtpError } from "@yasirdora/linkotp";

try {
  await auth.verifyCode({ email, code });
} catch (error) {
  if (LinkOtpError.is(error)) {
    error.code;               // "invalid_code" | "too_many_attempts" | …
    error.publicMessage;      // safe to render
    error.remainingAttempts;  // on invalid_code
  }
}
```

Codes: `invalid_email`, `rate_limited`, `invalid_challenge`, `invalid_code`, `too_many_attempts`, `invalid_token`, `binding_mismatch`, `delivery_failed`, `configuration_error`.

Expired, already-used, and never-existed all collapse into one error on purpose — distinguishing them tells an attacker holding a captured token whether it was ever valid.

---

## Development

```bash
npm install     # typescript, plus better-auth to type and test the plugin against
npm test        # node:test, no runner needed
npm run build   # tsc only, dual ESM + CJS
```

No bundler, no test framework, no `@types/node`. The SQL suite runs against real SQLite via `node:sqlite`, and the Better Auth suite runs against Better Auth's own adapter rather than a hand-written double.

---

## License

[MIT](https://github.com/Yasirdora/linkotp/blob/main/LICENSE) © 2026 [Yasir Dora.](https://ysr.design/)
