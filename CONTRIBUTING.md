# Contributing

Thanks for looking. This is a small, security-sensitive package, and the bar
for changes is correspondingly high.

## Getting set up

```bash
npm install     # installs exactly one package: typescript
npm run verify  # typecheck + tests
```

Requires Node 22.6 or newer for development, because the test suite runs
TypeScript directly through Node's type stripping. The published package
supports Node 18+.

There is no bundler, no test framework, and no `@types/node`. Tests use
`node:test`, the build is plain `tsc`, and the SQL suite runs against real
SQLite through `node:sqlite`.

## The dependency rule

**otplink has zero runtime dependencies and will keep it that way.** A pull
request that adds one to `dependencies` or `peerDependencies` will not be
merged. This is not minimalism for its own sake: an auth library sits on the
critical path of every sign-in, and every transitive dependency is a package
that can be compromised into that path.

The devDependency list is `typescript` and nothing else. Adding a linter, a
bundler, or a test runner needs a strong argument.

## Standards for a change

Everything in `src/` must:

- Use Web Standard APIs only. No Node built-ins — the package runs on Workers,
  Deno, and Bun, and `node:crypto` would break all three.
- Pass `npm run typecheck`. The config is strict, including
  `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`. Do not weaken it
  to make a change compile.
- Carry tests. Security properties in particular need a test that fails when
  the property is removed — verify this by actually removing it.
- Explain *why* in comments, not *what*. The reasoning behind a security
  decision is the part that stops someone undoing it in six months.

## Touching the store interface

`TokenStore.consume` is the load-bearing method: it must be a single atomic
compare-and-set. If you change the interface, update all three of the memory
store, the SQL store, and the conformance suite, and make sure the concurrency
check still fails a deliberately non-atomic implementation. There is a test for
that (`the conformance suite catches a non-atomic consume`) — it must keep
passing, which is to say the suite must keep failing bad stores.

## Adding a database

You probably do not need to. `createSqlStore` takes a two-method driver, so
most databases are a ten-line adapter in your own code, not a change here.

If a database genuinely cannot fit that interface, open an issue first.

## Security issues

Do not open a public issue or pull request. See [SECURITY.md](./SECURITY.md).

## Commits and releases

Commit messages describe the change and its reason. Releases are cut from
`main` after `npm run verify` and a build, with `CHANGELOG.md` updated in the
same commit.
