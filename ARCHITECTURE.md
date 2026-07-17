# Architecture — cognito-toolkit

Internal layout and design rationale. For usage see the [README](./README.md), the [wiki](https://github.com/uhop/cognito-toolkit/wiki), and `llms.txt` / `llms-full.txt`. For AI-agent working rules see [AGENTS.md](./AGENTS.md).

## What it is

The web-app glue for AWS Cognito auth: Koa and Express middleware bundles (token sourcing, request-state population, route guards, an auth-cookie convenience), a framework-free verifier adapter, and two holders for outbound OAuth2 `client_credentials` tokens. Token **verification itself is not implemented here** — it is delegated to AWS's official [aws-jwt-verify](https://github.com/awslabs/aws-jwt-verify), the package's single runtime dependency (itself dependency-free).

## Why v3 delegates verification

1.x carried a homegrown verifier; 2.0.0 rewrote it to zero dependencies and was never published: the survey showed `aws-jwt-verify` at parity-plus (multi-pool by issuer, JWKS rotation, `alg` pinning, claim checks, hydration) with AWS's maintenance behind it. Verification is the **commodity layer** — reimplementing it buys risk, not value. The **value layer** is what web apps still had to hand-roll around any verifier: where the token comes from, what an anonymous request looks like, 401-vs-403 guard semantics over Cognito's claims, and the login-once cookie flow. v3 keeps exactly that layer and absorbs the former sister packages (`koa-cognito-middleware`, `cognito-express-middleware`) as subpaths, so the family ships and versions as one unit.

## Module graph

```
index.js ──▶ aws-jwt-verify (CognitoJwtVerifier / JwtVerifier re-exports)
   │              (makeGetUser: verifier -> token => payload | null; prime() -> hydrate())
   └──▶ debug.js

koa.js ─────▶ index.js (makeGetUser)
   └────────▶ claims.js (getGroups / getScopes)
express.js ─▶ index.js (makeGetUser)
   └────────▶ claims.js

utils/lazy-access-token.js ──────▶ utils/fetch-token.js
utils/renewable-access-token.js ─▶ utils/fetch-token.js
```

## The adapter (`index.js`)

`makeGetUser(verifier, options?)` is the seam between the commodity and the glue:

- validates the verifier shape up front (`verify` must be a function — fail fast at composition time, not per request);
- an absent / empty token short-circuits to `null` **without touching the verifier** — anonymity is a normal state, not an error, so it never throws even under `throwOnError`;
- a failed verification resolves to `null` (logged via `NODE_DEBUG=cognito-toolkit`) or, under `throwOnError`, rethrows the aws-jwt-verify error so callers can tell _why_ the token failed;
- `prime()` maps to the verifier's `hydrate()` (JWKS pre-fetch for cold starts) and resolves harmlessly for stand-ins without one.

The payload type is generic and flows from the verifier in the `.d.ts` layer; any object with an async throwing `verify()` works (`TokenVerifier<P>`), which is also how the tests type structural stand-ins.

## The middleware bundles (`koa.js` / `express.js`)

`makeAuth(options)` returns a per-instance bundle — `{getUser, isAuthenticated, hasGroup, hasScope, isAllowed, setAuthCookie, stateUserProperty}`. The v1 middlewares hung the guards and the `stateUserProperty` knob on the module as mutable statics, coupling every consumer in the process; the factory closes over one options set instead (the same fix the 2.x utils made for the v1 token singletons).

The two files are deliberate near-twins, and small enough that sharing more than `claims.js` (the `cognito:groups` / `scope` readers) would cost more than it saves. Framework specifics they don't share:

- **Cookie plumbing** — Koa reads/writes via `ctx.cookies`; Express reads `req.cookies` (cookie-parser's surface, duck-typed) and writes via `res.cookie`.
- **Refresh timing** — the automatic auth-cookie refresh must land before headers flush: Koa runs it after `await next()` (Koa buffers the response), Express hooks `res.writeHead` (the last common gate before headers go out).
- **Guard responses** — `ctx.status = 401/403` vs `res.sendStatus(401/403)`.

Shared semantics, both sides: the token source is header-then-cookie (each disableable, `source` overrides both); tokens are used **bare** — no `Bearer` parsing (a custom `source` strips prefixes when needed); guards answer **401 for anonymous, 403 for authenticated-but-unauthorized**; an authenticated payload carries `_token` and a bound `setAuthCookie`; the cookie expires with the token and its `domain` defaults to the request **hostname** — not `host`, which Express 5 serves with the port attached, and a port is invalid in a cookie `Domain` (the cookie serializer rejects it).

The frameworks themselves are **duck-typed at runtime** — `src/` never imports `koa` or `express`; they are devDependencies for the tests and the `.d.ts` sidecars only (the sidecars use real framework types for consumer DX, per the fleet's framework-typed-sidecar convention).

## Token utilities (`utils/`)

Unrelated to verification: they obtain _outbound_ `client_credentials` access tokens from a user-pool domain's `/oauth2/token`. `fetch-token.js` is the shared internal POST (HTTP Basic `clientId:secret`, form body, JSON response; non-2xx and malformed-2xx both throw — a broken auth server is an error, not a "no token" state). Both holders are **factories** returning per-instance closures:

- `createLazyAccessToken` — fetches on demand, caches until shortly before expiry.
- `createRenewableAccessToken` — fetches once, then renews on a self-scheduling `setTimeout` that is `unref`ed so it never holds the event loop open.

## Testing (`tests/`)

Offline by design, no Docker, no AWS account:

- `helpers/mock-cognito.js` mints real signed JWTs (arbitrary claims, expiry, token use) and serves a matching JWKS + `/oauth2/token` over loopback `node:http`.
- **Verification tests don't use the mock's HTTP side**: aws-jwt-verify's Node fetcher is https-only, so the tests preload the mock's JWKS via `verifier.cacheJwks(...)` — deterministic and network-free. (Unknown-`kid` paths are aws-jwt-verify's own tested territory; this suite doesn't re-test the dependency.)
- The middleware suites spin up real Koa / Express apps over loopback `node:http` and drive them with `fetch` — sources (header / cookie / custom), all four guards, both auth-cookie refresh paths, and the custom-state-property wiring are exercised end-to-end on every runtime (Node / Bun / Deno).
- The mock's HTTP endpoints still back the `utils/` token-holder tests (`/oauth2/token`).

## Conventions

- ESM-only `.js` with hand-written `.d.ts` sidecars; no build step. (See [AGENTS.md](./AGENTS.md) § Code style.)
- One runtime dependency (`aws-jwt-verify`); Node 20+ / latest Bun / latest Deno.
- Default export with named mirror on every default-bearing module.
