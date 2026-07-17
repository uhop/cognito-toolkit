# AGENTS.md — cognito-toolkit (v3)

> `cognito-toolkit` is an **ESM-only** middleware family for AWS Cognito authentication & authorization in web apps. Token verification is delegated to AWS's official [aws-jwt-verify](https://github.com/awslabs/aws-jwt-verify) — the **single runtime dependency** (itself dependency-free); this package owns the glue above it: Koa and Express middleware bundles (`makeAuth` on the `./koa` / `./express` subpaths) with route guards (`isAuthenticated` / `hasGroup` / `hasScope` / `isAllowed`) and an auth-cookie convenience, the framework-free `makeGetUser(verifier, options?)` adapter (`token => Promise<payload | null>`, with `prime()`), and two `utils/` factories that fetch and cache OAuth2 `client_credentials` access tokens. `CognitoJwtVerifier` / `JwtVerifier` are re-exported from the root for one-stop imports. v3 absorbed the sister packages `koa-cognito-middleware` and `cognito-express-middleware` (now frozen re-export thunks) — the retire-the-commodity-keep-the-glue split: the verifier is the commodity, the middleware family is the product.

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
| `npm install`                       | Install dependencies (runtime: `aws-jwt-verify` only)                                   |
| `npm test`                          | Run the suite via tape-six on Node — no Docker, no network (offline mock + `cacheJwks`) |
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
│   ├── index.js / index.d.ts         # makeGetUser adapter + aws-jwt-verify re-exports
│   ├── koa.js / koa.d.ts             # makeAuth — Koa middleware bundle
│   ├── express.js / express.d.ts     # makeAuth — Express middleware bundle
│   ├── claims.js / claims.d.ts       # getGroups / getScopes claim readers (shared by both bundles)
│   ├── debug.js / debug.d.ts         # util.debuglog('cognito-toolkit') channel
│   └── utils/
│       ├── fetch-token.js / .d.ts            # internal client_credentials POST helper
│       ├── lazy-access-token.js / .d.ts      # createLazyAccessToken — on-demand cached token
│       └── renewable-access-token.js / .d.ts # createRenewableAccessToken — timer-renewed token
├── tests/
│   ├── test-get-user.js              # core adapter: valid / id-token / absent / rejected /
│   │                                 #   throwOnError / stand-in verifier / prime()
│   ├── test-koa.js                   # Koa e2e over loopback http: sources, guards, auth cookie
│   ├── test-express.js               # Express e2e over loopback http: same coverage
│   ├── test-tokens.js                # lazy + renewable access-token holders
│   ├── test-smoke.js                 # ESM export surface (incl. subpaths)
│   ├── test-smoke.cjs                # require(esm) smoke (Node-only)
│   ├── test-typed.ts                 # consumer-facing typings smoke (ts-test)
│   └── helpers/mock-cognito.js       # in-process Cognito stand-in: signs JWTs, serves JWKS
│                                     #   + /oauth2/token (verification tests use cacheJwks instead)
└── wiki/                             # Published wiki — git submodule
```

The published tarball ships **`src/`, `README.md`, `LICENSE`, `llms.txt`, `llms-full.txt`, `package.json`**. Tests, AI rule files, `.github/`, and the wiki stay out (verify via `npm pack --dry-run`).

## Code style

- **ESM only** — `import` / `export`, `"type": "module"`. No CommonJS source, no transpiler. CJS consumers reach the package via `require(esm)` (Node 20.19+ / 22.12+) and the **named** exports: `const {makeAuth} = require('cognito-toolkit/koa')`.
- **`.js` + hand-written `.d.ts` sidecars** — not true TypeScript. Both files live next to each other (`foo.js` ↔ `foo.d.ts`). Every exported symbol carries JSDoc on the `.d.ts` side; `.js` files carry no JSDoc (the rare `/** @type */` cast for `js-check` is fine).
- **Default export with named mirror** — a module that has a `default` export also exports the same value by name (`export default makeAuth; export {makeAuth}`). ESM imports use the default or the name; CJS destructures the name.
- **One runtime dependency: `aws-jwt-verify`. Keep it that way.** The verifier is deliberately adopted, not owned (see ARCHITECTURE.md § Why v3 delegates); everything else stays on Node built-ins. **Frameworks are duck-typed** — `koa` / `express` (+ `@types/*`) are devDependencies for tests and typings only; `src/` never imports them.
- **Node 20+** target. Also runs on the latest Bun and Deno.
- **No `any` in `.d.ts`.** Use proper shapes or `unknown`. (Generics flow the payload type from the verifier.)
- **Arrow functions + FP style preferred.** No classes — factories returning per-instance closures. Never reintroduce module-level mutable singletons: the v1 middlewares' static `getUser.stateUserProperty` / shared guards were exactly that footgun, and `makeAuth`'s per-instance bundle is the fix. Don't add statics to it.
- **Security posture** — verification (algorithm policy, signature, JWKS rotation, claim checks) is aws-jwt-verify's domain; do not add verification logic here. The glue's own invariants: tokens are used **bare** (no `Bearer` parsing anywhere); an absent token is anonymous (`null`), never an error, even under `throwOnError`; guards answer 401 for anonymous vs 403 for unauthorized; cookie `domain` uses the request **hostname** (never `host` — Express 5 keeps the port there and the cookie serializer rejects it).
- **Prettier** enforces formatting (`.prettierrc`, `printWidth: 160`). Run `npm run lint:fix` before commits.
- **Two tsconfig files:** `tsconfig.json` strict (for `.d.ts` sidecars + `.ts` tests), `tsconfig.check.json` lenient + `checkJs` (catches unused vars / undeclared refs in `.js`). Avoid `({a, b} = {})` destructure-defaults in `.js` — they infer the empty type and fail `js-check`; take a named param and destructure with `|| {}` inside.
- **Pre-increment when the value is discarded** (`++i` / `--i`, not `i++` / `i--`). Cross-project style rule.
- **No comments that narrate the code.** Comments are short _why_-markers only (a non-trivial decision / constraint, or an algorithm reference) — never a restatement of _what_ the code does.

## Architecture

`makeGetUser(verifier, options?)` (in `index.js`) is the seam between the commodity and the glue: it validates the verifier shape, short-circuits absent tokens to `null`, maps verification failures to `null` (debug-logged) or rethrows under `throwOnError`, and exposes `prime()` → `verifier.hydrate()`. Both middleware modules build on it.

`koa.js` / `express.js` are deliberate near-twins (`makeAuth(options)`): resolve options, build a token source (header → cookie fallback, or a custom `source`), authenticate in `getUser`, attach `_token` + a bound `setAuthCookie` to the payload, and expose the guards. Framework quirks live where they belong: Koa refreshes the auth cookie after `await next()`, Express hooks `res.writeHead`; Koa reads cookies natively, Express expects `req.cookies` (cookie-parser). Shared claim readers (`cognito:groups`, `scope`) sit in `claims.js`.

Testing is offline by design: `tests/helpers/mock-cognito.js` mints signed JWTs and the verification tests preload its JWKS via `verifier.cacheJwks(...)` — no network (aws-jwt-verify's Node fetcher is https-only, so the loopback http server can't serve it JWKS; `cacheJwks` sidesteps that). The middleware tests run real Koa / Express apps over loopback `node:http` and drive them with `fetch`. The mock's HTTP endpoints still serve the `utils/` token tests.
