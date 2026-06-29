# AGENTS.md — cognito-toolkit (v2)

> `cognito-toolkit` is a **zero-runtime-dependency, ESM-only** micro-library that validates AWS Cognito JWTs (id / access tokens) for authentication & authorization in web apps. The main export `makeGetUser(pools, options?)` returns an async validator that fetches the pool's JWKS, verifies the signature under a configurable algorithm policy (default `['RS256']`, what Cognito uses), checks issuer / `kid` / `exp` / `nbf` plus an optional `validate` hook, and resolves to the decoded payload — or `null`. It also works against non-Cognito OIDC issuers via `PoolOptions.issuer` + `algorithms`. Two `utils/` helpers fetch and cache OAuth2 `client_credentials` access tokens. Verification is fully offline (no AWS SDK, no network except the public JWKS fetch); it builds on Node built-ins — `crypto`, `fetch`, `util.debuglog`.

For published API docs see the [wiki](https://github.com/uhop/cognito-toolkit/wiki).

## Setup

This project uses a git submodule for the wiki:

```bash
git clone --recursive https://github.com/uhop/cognito-toolkit.git
cd cognito-toolkit
npm install
```

If you cloned without `--recursive`, run `git submodule update --init` to populate `wiki/`.

## Commands

| Command                             | What it does                                                                            |
| ----------------------------------- | --------------------------------------------------------------------------------------- |
| `npm install`                       | Install dev dependencies (there are no runtime dependencies)                            |
| `npm test`                          | Run the suite via tape-six on Node — no Docker, no network (uses an in-process mock)    |
| `npm run test:bun`                  | Manual — same suite under Bun (excluding `.cjs` tests)                                  |
| `npm run test:deno`                 | Manual — same suite under Deno (excluding `.cjs` tests)                                 |
| `npm run ts-test`                   | Run the TypeScript test files (`tests/test-*.ts`) via tape-six's native `.ts` support   |
| `npm run ts-check`                  | Strict `tsc --noEmit` over `.ts` / `.d.ts` files                                        |
| `npm run js-check`                  | `tsc --project tsconfig.check.json` — JS lint via type-checker (unused vars / bad refs) |
| `npm run lint` / `npm run lint:fix` | Prettier check / fix                                                                    |

There is no build step. The published tarball ships `src/` (the `.js` + `.d.ts` pairs) plus `llms.txt` / `llms-full.txt`.

## Project structure

```
cognito-toolkit/
├── src/                              # Published code (ESM .js + .d.ts sidecars)
│   ├── index.js / index.d.ts         # makeGetUser — default + named export
│   ├── verify.js / verify.d.ts       # verifyToken — alg policy + sig + iss / kid / exp / nbf / validate
│   ├── key-store.js / key-store.d.ts # JWKS fetch + per-kid cache + rotation refresh
│   ├── debug.js / debug.d.ts         # util.debuglog('cognito-toolkit') channel
│   └── utils/
│       ├── fetch-token.js / .d.ts            # internal client_credentials POST helper
│       ├── lazy-access-token.js / .d.ts      # createLazyAccessToken — on-demand cached token
│       └── renewable-access-token.js / .d.ts # createRenewableAccessToken — timer-renewed token
├── tests/
│   ├── test-verify.js                # verify path: valid / expired / nbf / wrong-iss /
│   │                                 #   unknown-kid / tampered / alg:none / rotation / multi-pool
│   ├── test-algorithms.js            # algorithm policy (allowlist / predicate) + validate hook + ES256
│   ├── test-tokens.js                # lazy + renewable access-token holders
│   ├── test-smoke.js                 # ESM export surface
│   ├── test-smoke.cjs                # require(esm) smoke (Node-only)
│   ├── test-typed.ts                 # consumer-facing typings smoke (ts-test)
│   └── helpers/mock-cognito.js       # in-process Cognito stand-in: signs RS256 JWTs,
│                                     #   serves JWKS + /oauth2/token, rotates keys
└── wiki/                             # Published wiki — git submodule
```

The published tarball ships **`src/`, `README.md`, `LICENSE`, `llms.txt`, `llms-full.txt`, `package.json`**. Tests, AI rule files, `.github/`, and the wiki stay out (verify via `npm pack --dry-run`).

## Code style

- **ESM only** — `import` / `export`, `"type": "module"`. No CommonJS source, no transpiler. CJS consumers reach the package via `require(esm)` (Node 20.19+ / 22.12+) and the **named** export: `const {makeGetUser} = require('cognito-toolkit')`.
- **`.js` + hand-written `.d.ts` sidecars** — not true TypeScript. Both files live next to each other (`foo.js` ↔ `foo.d.ts`). Every exported symbol carries JSDoc on the `.d.ts` side; `.js` files carry no JSDoc.
- **Default export with named mirror** — a module that has a `default` export also exports the same value by name (`export default makeGetUser; export {makeGetUser}`). ESM imports use the default; CJS destructures the name.
- **Zero runtime dependencies.** Use Node built-ins (`node:crypto`, global `fetch`, `node:util`). Don't add a runtime dependency without a strong reason — the whole point is that consumers get a tiny, auditable verifier.
- **Node 20+** target. Also runs on the latest Bun and Deno.
- **No `any` in `.d.ts`.** Use proper shapes or `unknown`.
- **Arrow functions + FP style preferred.** No classes here — the toolkit is a handful of factory functions closing over per-instance state. Never reintroduce module-level mutable singletons (the v1 footgun that broke multi-pool / multi-credential use).
- **Security posture** — the token header's `alg` is **never used to _select_ the algorithm**; it is only gated against the caller's `algorithms` policy (default `['RS256']`). Only the asymmetric JWA family is mappable in `verify.js` (`ALGORITHMS` / `SUPPORTED_ALGORITHMS`) — `HS*` and `none` have no entry, so widening the policy can never enable an algorithm-confusion or `alg:none` attack (the keys are asymmetric public keys from the JWKS). Verification uses Node's vetted `crypto.verify`, not a hand-rolled primitive. Keep both invariants.
- **Prettier** enforces formatting (`.prettierrc`, `printWidth: 160`). Run `npm run lint:fix` before commits.
- **Two tsconfig files:** `tsconfig.json` strict (for `.d.ts` sidecars + `.ts` tests), `tsconfig.check.json` lenient + `checkJs` (catches unused vars / undeclared refs in `.js`). Avoid `({a, b} = {})` destructure-defaults in `.js` — they infer the empty type and fail `js-check`; take a named param and destructure with `|| {}` inside.
- **Pre-increment when the value is discarded** (`++i` / `--i`, not `i++` / `i--`). Cross-project style rule.
- **No comments that narrate the code.** Comments are short _why_-markers only (a non-trivial decision / constraint, or an algorithm reference) — never a restatement of _what_ the code does.

## Architecture

`makeGetUser(pools, globalOptions?)` is the composition root. It normalizes `pools` to an array, derives each issuer URL (`https://cognito-idp.<region>.amazonaws.com/<userPoolId>`, or an explicit `issuer` override), builds one shared **key store**, and returns the validator `token => Promise<payload | null>`.

- **`key-store.js`** owns JWKS state. `get(kid)` returns the cached `KeyObject` or, on a miss, refreshes the JWKS (deduped via a single in-flight promise, rate-limited by `minRefreshInterval`). A cache miss is the **key-rotation** signal — Cognito rotates signing keys, and the v1 "fetch once, cache forever" behavior is exactly what this fixes.
- **`verify.js`** is pure given a key store. It splits the JWT, decodes the header / payload (rejecting malformed input without throwing), gates `header.alg` through `isAlgorithmAllowed` and the `ALGORITHMS` map (asymmetric-only), checks `iss` ∈ issuers, resolves the key by `kid`, verifies the signature with `crypto.verify` (the digest + padding / `dsaEncoding` come from the matched algorithm spec, not the header), checks `exp` / `nbf` (with optional `clockTolerance`), and finally runs the optional `validate(payload, header)` hook. Any failure → `null`.
- **`utils/`** are unrelated to verification — they obtain _outbound_ `client_credentials` access tokens from a Cognito domain's `/oauth2/token`. Both are **factories** returning per-instance closures (`createLazyAccessToken`, `createRenewableAccessToken`); the renewable one `unref`s its refresh timer so it never holds the process open.

Testing is offline by design: `tests/helpers/mock-cognito.js` is a real loopback HTTP server that mints RS256 JWTs with the right claims, serves the matching JWKS, answers `/oauth2/token`, and can rotate keys or sign with a foreign key — so every verify branch (including rotation and tamper) is exercised deterministically with no Docker and no AWS account.
