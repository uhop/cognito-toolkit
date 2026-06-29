# Architecture — cognito-toolkit

Internal layout and design rationale. For usage see the [README](./README.md), the [wiki](https://github.com/uhop/cognito-toolkit/wiki), and `llms.txt` / `llms-full.txt`. For AI-agent working rules see [AGENTS.md](./AGENTS.md).

## What it is

A tiny, auditable verifier for AWS Cognito JWTs, plus two helpers for obtaining OAuth2 `client_credentials` access tokens. It deliberately uses **no AWS SDK** and **no runtime dependencies** — Cognito token verification is offline RSA signature checking against the pool's published JWKS, which Node's built-in `crypto` does natively. The library is the orchestration around `crypto`, `fetch`, and `util.debuglog`.

## Module graph

```
index.js ──▶ key-store.js ──▶ debug.js
   │              (JWKS fetch + per-kid cache + rotation refresh)
   └──▶ verify.js ──▶ debug.js
              (split, decode, gate alg, check iss/kid/sig/exp/nbf/validate)

utils/lazy-access-token.js ──────▶ utils/fetch-token.js
utils/renewable-access-token.js ─▶ utils/fetch-token.js
```

`index.js` is the composition root. `makeGetUser` normalizes `pools` to an array, derives issuer URLs, normalizes `algorithms` (array or predicate) into an `isAlgorithmAllowed` function, constructs one shared key store, and returns a closure `token => verifyToken(token, {issuers, keyStore, isAlgorithmAllowed, validate, clockTolerance})`. No module-level state — every call to `makeGetUser` is fully independent (the v1 singleton bug is gone). `SUPPORTED_ALGORITHMS` is re-exported here.

## Verification pipeline (`verify.js`)

Pure given a key store. Order matters and is chosen to reject as early and as cheaply as possible:

1. Reject non-strings and tokens without exactly three `.`-separated segments.
2. base64url-decode the header and payload as JSON, returning `null` (not throwing) on malformed bytes.
3. **Gate `alg` through the `algorithms` policy** (default `['RS256']`), then look it up in the internal `ALGORITHMS` map. The header `alg` is only ever _checked_ — it never _selects_ how verification runs (the digest + padding / `dsaEncoding` come from the matched map entry). The map holds only asymmetric algorithms (`RS*`/`PS*`/`ES*`), so `HS*` and `none` have no entry and can never be verified — algorithm-confusion and `alg:none` stay impossible even under a permissive policy.
4. Check `iss` ∈ allowed issuers — before any key lookup, so a foreign-issuer token never touches the store.
5. Resolve the signing key by `kid` from the key store.
6. Verify the signature over `header.payload` with `crypto.verify(digest, …, {key, ...options}, sig)` using the matched algorithm's parameters. A key-type / algorithm mismatch (e.g. an `ES256` header over an RSA key) throws and is caught → `null`.
7. Check `exp` and `nbf` against the current time with optional `clockTolerance`.
8. Run the optional `validate(payload, header)` hook (for `token_use`, `aud`, provider-specific claims); a falsy result or a throw → `null`.

## Key store (`key-store.js`)

Owns all JWKS state for a validator. `get(kid)`:

- returns the cached `KeyObject` on a hit;
- on a miss, treats it as a possible **key rotation** and refreshes the JWKS — but dedupes concurrent refreshes through a single in-flight promise and rate-limits via `minRefreshInterval`.

`refresh()` fetches every issuer's `/.well-known/jwks.json` in parallel, imports each JWK to a `KeyObject` via `createPublicKey({key, format: 'jwk'})`, and merges them into the `kid → KeyObject` map. Fetch / parse / import errors are logged through the debug channel and skipped, never thrown — a transient JWKS outage degrades to "token not yet verifiable" rather than a crash. This fixes the v1 behavior of fetching the JWKS exactly once and caching it forever, which silently broke verification after a pool rotated its keys.

## Token utilities (`utils/`)

Unrelated to verification: they obtain _outbound_ `client_credentials` access tokens from a user-pool domain's `/oauth2/token`. `fetch-token.js` is the shared internal POST (HTTP Basic `clientId:secret`, form body, JSON response). Both holders are **factories** returning per-instance closures:

- `createLazyAccessToken` — fetches on demand, caches until shortly before expiry.
- `createRenewableAccessToken` — fetches once, then renews on a self-scheduling `setTimeout` that is `unref`ed so it never holds the event loop open.

## Testing (`tests/helpers/mock-cognito.js`)

Verification is offline, so the tests don't need AWS or Docker — they need a faithful issuer. `mock-cognito.js` is a real loopback `node:http` server that generates RSA (or EC, for `ES*`) keypairs, signs JWTs with correct `iss` / `kid` / `token_use` claims, serves the matching JWKS, answers `/oauth2/token`, and can rotate keys or sign with a key absent from the JWKS. That lets the suite drive every branch — valid / expired / not-yet-valid / wrong-issuer / unknown-kid / tampered / `alg:none` / rotation / multi-pool / algorithm-policy / `validate` — deterministically. A self-owned mock beats a third-party emulator here precisely because there is no AWS query semantics to reproduce; there is only signing and serving, which the mock does exactly.

## Conventions

- ESM-only `.js` with hand-written `.d.ts` sidecars; no build step. (See [AGENTS.md](./AGENTS.md) § Code style.)
- Zero runtime dependencies; Node 20+ / latest Bun / latest Deno.
- Default export with named mirror on every default-bearing module.
