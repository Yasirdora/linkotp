# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, the minor version is treated as the breaking
slot: 0.1.x to 0.2.0 may break, 0.1.0 to 0.1.1 will not.

## [Unreleased]

### Added

- `otplink/better-auth` — a Better Auth plugin. `GET /otplink/verify` renders a
  confirmation page and consumes nothing; only the `POST` it submits redeems
  the token, so mail security scanners cannot spend the credential. Addresses
  [better-auth#6985](https://github.com/better-auth/better-auth/discussions/6985).
- `createBetterAuthStore` — a `TokenStore` over Better Auth's database adapter,
  so the plugin needs no second database connection. Passes the bundled
  conformance suite against Better Auth's own adapter.
- `otplinkSchema` — the plugin's table, in Better Auth's schema format, so
  `@better-auth/cli generate` produces the migration.

### Changed

- `better-auth` is declared as an **optional** peer dependency. `dependencies`
  stays empty, and the peer installs nothing for anyone who does not import
  `otplink/better-auth`. CI now asserts that every peer is optional rather than
  that there are none.

### Notes

- Better Auth's `Where` clause compares a field to a literal and never to
  another field, so the guard `attempts < maxAttempts` is inexpressible through
  it. The plugin's table stores `attemptsRemaining` and guards
  `attemptsRemaining > 0`, which is equivalent and keeps `consume` a single
  atomic compare-and-set.
- Better Auth types `updateMany` as `Promise<number>`, but its Drizzle adapter
  returns the driver's result object and its memory adapter returns the updated
  record. The store normalizes every shape and treats anything unrecognized as
  zero rows, failing closed.

## [0.1.0]

Initial release.

### Added

- `createOtpLink` — issues one challenge carrying two independent secrets, a
  typed code and a link token, delivered in a single message. Redeeming either
  arm retires the other.
- Keyed digests (HMAC-SHA256) for both secrets, domain-separated, with the code
  digest salted by the address so it cannot be replayed across accounts.
- Atomic single-use redemption expressed as one guarded compare-and-set.
- `otplink/http` — a Fetch-API handler whose `GET` verify route consumes
  nothing, so mail scanners and prefetchers cannot burn a link. Ships the CSP
  nonce, security headers, same-origin enforcement, and redirect sanitizing.
- `otplink/stores` — an in-memory store and a SQL store speaking to any
  database through a two-method driver. SQLite, Postgres, and MySQL dialects.
- `otplink/testing` — a 17-check store conformance suite, including a
  concurrency check that fails a read-then-write `consume`.
- Configuration validated at startup: weak secrets, non-https origins, and
  under-entropy tokens are rejected before the first request.
- Enumeration-resistant `shouldSend` with a latency floor on `start`.
- Optional device binding, tying a link to the browser that requested it.
- Secret rotation via `rotation.previous`, so rotating does not invalidate
  challenges already in flight.
- Responsive, theme-aware default email template with a plain-text alternative.

[Unreleased]: https://github.com/Yasirdora/otplink/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Yasirdora/otplink/releases/tag/v0.1.0
