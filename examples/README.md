# Examples

## `minimal-server.ts`

A complete sign-in flow in one file, with nothing installed.

```bash
node examples/minimal-server.ts
```

Open <http://localhost:3000>, enter any address, and the code and link are
printed to the console instead of being emailed.

### Seeing the scanner defence work

The reason `GET` and `POST` do different things is easiest to believe by
watching it. With the server running, request a challenge and copy the
verification URL from the console, then:

```bash
curl -sI "http://localhost:3000/auth/verify?token=PASTE_TOKEN"
```

Three things to notice:

1. It returns `200` with the confirmation page.
2. There is no `Set-Cookie` — no session was created.
3. The link **still works** afterwards.

That is a mail scanner's request. Repeat it as many times as you like; the
challenge survives. Only the `POST` that the page submits redeems it:

```bash
curl -si -X POST http://localhost:3000/auth/verify \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Sec-Fetch-Site: same-origin' \
  -d "token=PASTE_TOKEN"
```

`303`, with a session cookie. Run it a second time and it redirects to
`?error=invalid_token`: single use, enforced by the database, not by the
application.

### What to change for production

The example takes three shortcuts, each marked in the source:

| Example | Production |
|---|---|
| `createMemoryStore()` | `createSqlStore({ driver, dialect })` |
| Mailer prints to the console | Your transport — Resend, SES, Postmark, Gmail API |
| `onVerified` sets a plaintext cookie | A signed session from your session library |

Everything else — the challenge protocol, the `GET`/`POST` split, the security
headers, the atomic redemption — is exactly what you would deploy.
