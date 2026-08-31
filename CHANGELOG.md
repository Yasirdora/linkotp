# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, the minor version is treated as the breaking
slot: 0.1.x to 0.2.0 may break, 0.1.0 to 0.1.1 will not.

## [Unreleased]

## [0.2.0] — 2026-08-31

### Added

- `linkotp/better-auth` — a Better Auth plugin. `GET /linkotp/verify` renders a
  confirmation page and consumes nothing; only the `POST` it submits redeems
  the token, so mail security scanners cannot spend the credential. Addresses
  [better-auth#6985](https://github.com/better-auth/better-auth/discussions/6985).
- `createBetterAuthStore` — a `TokenStore` over Better Auth's database adapter,
  so the plugin needs no second database connection. Passes the bundled
  conformance suite twice: on the memory adapter, and on real SQLite through
  Better Auth's Kysely adapter with the table created by Better Auth's own
  migrator. The SQL run is what establishes that the guarded `updateMany`
  compiles to a single `UPDATE` and that a real row lock — not JavaScript's
  single thread — elects the winner, along with `eq null` compiling to
  `IS NULL` and `date` columns comparing correctly.
- `linkotpSchema` — the plugin's table, in Better Auth's schema format, so
  `@better-auth/cli generate` produces the migration.
- `linkotp/better-auth/client` — the client plugin, so `authClient.signIn.linkotp`
  exists and is typed by inference from the server half. It imports the server
  plugin as a type only, so nothing but a dependency-free constants module
  reaches the browser bundle.
- The link flow redirects to `errorCallbackURL` with `?error=<code>` when a
  challenge has expired, been redeemed, or run out of attempts. Those are the
  ordinary end of a challenge's life and the person clicking is in a browser,
  so a JSON error body was the wrong answer.

### Changed

- `better-auth` is declared as an **optional** peer dependency, `>=1.7.0`.
  `dependencies` stays empty, and the peer installs nothing for anyone who does
  not import `linkotp/better-auth`. CI now asserts that every peer is optional
  rather than that there are none. The floor is 1.7 because that release
  renamed `getIp` to `getIP` and added a required provisioning-source argument
  to `internalAdapter.createUser`.

### Notes

- Better Auth's `Where` clause compares a field to a literal and never to
  another field, so the guard `attempts < maxAttempts` is inexpressible through
  it. The plugin's table stores `attemptsRemaining` and guards
  `attemptsRemaining > 0`, which is equivalent and keeps `consume` a single
  atomic compare-and-set.
- Better Auth types `updateMany` as `Promise<number>`. Its first-party adapters
  honour that as of 1.7; through 1.6.2 the Drizzle adapter returned the raw
  driver result object and the memory adapter returned the updated record.
  The store reads every documented driver shape — including mysql2's
  single-element `[ResultSetHeader]` tuple and postgres-js's Array subclass,
  both of which are misread by a naive `Array.length` — and throws on a shape
  it cannot read rather than reporting zero, so an adapter incompatibility
  cannot masquerade as an expired link.
- New-user provisioning reports `method: "magic-link"` or `"email-otp"`
  according to which arm the user actually redeemed, so an application's
  `validateUserInfo` gate sees a method it recognizes.

## [0.1.0]

Initial release.

### Added

- `createLinkOtp` — issues one challenge carrying two independent secrets, a
  typed code and a link token, delivered in a single message. Redeeming either
  arm retires the other.
- Keyed digests (HMAC-SHA256) for both secrets, domain-separated, with the code
  digest salted by the address so it cannot be replayed across accounts.
- Atomic single-use redemption expressed as one guarded compare-and-set.
- `linkotp/http` — a Fetch-API handler whose `GET` verify route consumes
  nothing, so mail scanners and prefetchers cannot burn a link. Ships the CSP
  nonce, security headers, same-origin enforcement, and redirect sanitizing.
- `linkotp/stores` — an in-memory store and a SQL store speaking to any
  database through a two-method driver. SQLite, Postgres, and MySQL dialects.
- `linkotp/testing` — a 17-check store conformance suite, including a
  concurrency check that fails a read-then-write `consume`.
- Configuration validated at startup: weak secrets, non-https origins, and
  under-entropy tokens are rejected before the first request.
- Enumeration-resistant `shouldSend` with a latency floor on `start`.
- Optional device binding, tying a link to the browser that requested it.
- Secret rotation via `rotation.previous`, so rotating does not invalidate
  challenges already in flight.
- Responsive, theme-aware default email template with a plain-text alternative.

[Unreleased]: https://github.com/Yasirdora/linkotp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Yasirdora/linkotp/releases/tag/v0.1.0
