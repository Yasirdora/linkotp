# Security

## Reporting a vulnerability

Report privately through [GitHub Security Advisories](https://github.com/Yasirdora/otplink/security/advisories/new). Please do not open a public issue for a suspected vulnerability.

Expect an acknowledgement within 72 hours and an assessment within seven days. Fixes for confirmed issues ship as a patch release with an advisory; you will be credited unless you prefer otherwise.

Supported: the latest minor release. Pre-1.0, that means the latest release.

---

## Threat model

### What otplink defends against

**A stolen database.** Neither secret is stored in plaintext. Both are HMAC-SHA256 digests keyed by an application secret held in the environment, not the database. Recovering a six-character code from a plain SHA-256 is minutes of GPU time against a 10⁹ keyspace; without the key, it is not possible at all. This is why `secret` is mandatory and why anything under 32 characters is rejected at startup.

**A captured link.** The token is 48 characters over a 62-character alphabet — about 286 bits. It is single-use, enforced by a guarded atomic `UPDATE` rather than by application logic, and it expires. Two concurrent redemptions elect exactly one winner.

**Link scanners and prefetchers.** `GET` on the verify route consumes nothing. Only the `POST` submitted by the confirmation page redeems the token. Mail security appliances issue `GET` and stop.

**Brute force against the code.** ~30 bits, a per-challenge attempt ceiling re-checked inside the atomic guard, a per-address send cap, and an optional pluggable rate limiter. Exhausting the ceiling retires the challenge permanently — the correct code stops working too.

**Cross-account replay.** The code digest is salted with the address, so a digest valid for one account cannot be presented for another.

**Account enumeration.** `shouldSend` suppresses delivery while returning a byte-identical result, and `start` is padded to a latency floor so the suppressed path does not return faster. Verification errors do not distinguish expired from consumed from never-existed.

**Login CSRF.** State-changing `POST`s are validated against `Sec-Fetch-Site`, falling back to `Origin`. Without this, an attacker can sign a victim into the *attacker's* account and harvest what the victim then does.

**Open redirects.** Every redirect target must be a single-slash-prefixed same-origin path. `//evil.test`, `/\evil.test`, and absolute URLs are discarded rather than rewritten, because rewriting attacker input tends to produce a second bypass.

**Token leakage from the browser.** `Referrer-Policy: no-referrer` on every response touching a token, `Cache-Control: no-store`, `X-Robots-Tag: noindex`, and `history.replaceState` to strip the token from the address bar on load.

**Injection into the confirmation page.** `default-src 'none'` with a fresh per-response nonce; every interpolated value is HTML-escaped, including ones that "cannot" contain markup.

**Modulo bias in generated secrets.** Rejection sampling, not `byte % alphabet.length`. Over a 62-character alphabet the naive form makes the first eight characters ~25% more likely, measurably shrinking the keyspace.

**SQL injection through configuration.** Table names cannot be parameterized, so a configured name is validated against a strict identifier grammar before interpolation.

---

### What otplink does not defend against

These are real, and they are yours to handle.

**A compromised mailbox.** Anyone reading the inbox can sign in. This is inherent to email as an authentication factor. If that is unacceptable, email is the wrong factor — add a second one, or use passkeys.

**A compromised application secret.** The secret keys every digest. Leak it *and* the database and the pending challenges are recoverable. Keep it in a secrets manager, and rotate it with `rotation.previous` so in-flight challenges survive.

**Distributed rate limiting.** The bundled `createMemoryRateLimiter` is per-process. Behind a load balancer, the effective limit multiplies by the instance count; on serverless it may do nothing at all. Implement `RateLimiter` over Redis, a Durable Object, or your gateway.

**Session security after verification.** otplink stops at proving an address. Cookie flags, rotation, revocation, fixation, and idle timeout belong to your session library.

**Bot signups.** `guard` is where a CAPTCHA or reputation check goes. Nothing is wired in by default.

**Mail transport security.** Whether the message travels over TLS, and who can read it in transit or at rest at the provider, is between you and your mail vendor.

---

### Known residual risks

Stated plainly rather than buried.

**Timing equalization is a floor, not a mask.** `minimumStartDurationMs` removes the obvious signal — a fast reject versus a slow send — but a genuinely slow transport still stands out against a suppressed send that returns at the floor. Queue delivery instead of awaiting it if you need the timing to be truly flat.

**`remainingAttempts` is a weak enumeration signal.** Distinguishing `too_many_attempts` from `invalid_code` reveals whether a live challenge exists for an address. This is a deliberate trade: the alternative is a user who cannot tell why retrying never works. Omit the field from your API response if your threat model prefers otherwise.

**The token appears in a URL.** Inherent to magic links. It is mitigated (`no-referrer`, `no-store`, single use, short TTL, stripped from history) but the token still reaches the server's access log. Configure your log pipeline to drop or redact the query string on the verify path.

**A JavaScript-executing scanner can submit the form.** The default `confirmation: "auto"` defeats every scanner that does not run scripts, which is the overwhelming majority. `confirmation: "manual"` requires a real click and closes the remainder, at the cost of one interaction.

**Device binding fails closed.** With `binding.enabled`, a mismatch burns the challenge rather than offering a retry, because a mismatch means someone other than the initiator presented the secret. It also breaks "request on laptop, click on phone". Off by default for that reason.

**Local-part case folding.** Addresses are lowercased entirely. RFC 5321 declares the local part case-sensitive; every mainstream provider disagrees. Preserving case would let `User@x.com` and `user@x.com` become two accounts. Dots and `+tags` are deliberately *not* stripped, since those rules are provider-specific.

---

## Deployment checklist

- [ ] `secret` is 32+ random characters from a secrets manager, not source control
- [ ] `baseUrl` is https
- [ ] A distributed `rateLimiter` is configured if you run more than one instance
- [ ] `guard` performs a CAPTCHA or reputation check on `start`
- [ ] Access logs drop or redact the query string on the verify path
- [ ] `shouldSend` gates sign-ups if registration is closed
- [ ] Session cookies from `onVerified` are `HttpOnly`, `Secure`, `SameSite`
- [ ] `sweep()` runs periodically to keep the table small (optional; expiry is enforced regardless)
- [ ] A custom store passes `checkStoreConformance` in your CI
