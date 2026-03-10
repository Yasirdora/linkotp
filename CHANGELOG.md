# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, the minor version is treated as the breaking
slot: 0.1.x to 0.2.0 may break, 0.1.0 to 0.1.1 will not.

## [Unreleased]

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
