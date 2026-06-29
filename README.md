# `cognito-toolkit` [![NPM version][npm-img]][npm-url]

[npm-img]: https://img.shields.io/npm/v/cognito-toolkit.svg
[npm-url]: https://npmjs.org/package/cognito-toolkit

Validate [AWS Cognito](https://aws.amazon.com/cognito/) JWTs (id / access tokens) for authentication & authorization — **zero runtime dependencies, ESM-only**. Point it at a user pool, hand it a token, get back the decoded payload or `null`. The signature is verified against the pool's JWKS under a configurable algorithm policy (default RS256, what Cognito uses), keys are refreshed automatically on rotation, and the whole thing runs on Node built-ins — no AWS SDK. It also works against other OIDC issuers via the `issuer` + `algorithms` options.

Companion middleware built on this toolkit:

- Express: https://github.com/uhop/cognito-express-middleware
- Koa: https://github.com/uhop/koa-cognito-middleware

> **v2 is a breaking, ESM-only rewrite of v1.** The `makeGetUser` contract is unchanged; the import and the `utils/` API changed. See [Migrating from v1](#migrating-from-v1).

## Install

```sh
npm install cognito-toolkit
```

Requires Node 20+ (also runs on the latest Bun and Deno). ESM-only; CommonJS consumers load it via `require(esm)` and the named export.

## Usage

```js
import makeGetUser from 'cognito-toolkit';

// build a validator once
const getUser = makeGetUser({
  region: 'us-east-1',
  userPoolId: 'us-east-1_MY_USER_POOL'
});

// ...then on every request, with a token from a header or cookie:
const user = await getUser(authHeader || authCookie);

if (user) {
  console.log('Authenticated user:\n' + JSON.stringify(user, null, 2));
} else {
  console.log('User was not authenticated.');
}
```

Multiple pools — a token from any of them is accepted:

```js
const getUser = makeGetUser([
  {region: 'us-east-1', userPoolId: 'us-east-1_AAA'},
  {region: 'us-west-2', userPoolId: 'us-west-2_BBB'}
]);
```

CommonJS:

```js
const {makeGetUser} = require('cognito-toolkit');
```

Enable debug logging with the `NODE_DEBUG=cognito-toolkit` environment variable.

## API

### `makeGetUser(pools, globalOptions?)`

Returns an async validator `(token) => Promise<payload | null>`.

`pools` is one pool object or an array of them. Each pool is either a Cognito pool:

- `region` &mdash; **required** string, an AWS region such as `'us-east-1'`.
- `userPoolId` &mdash; **required** string, a user pool id such as `'us-east-1_MY_USER_POOL'`.

…or an explicit issuer (for a custom OIDC provider or testing):

- `issuer` &mdash; full issuer URL, replacing `region` + `userPoolId`. The JWKS is read from `${issuer}/.well-known/jwks.json`.

`globalOptions` (optional):

- `audience` &mdash; **strongly recommended.** App client id(s) (string or array). The token's `aud` (id tokens) or `client_id` (access tokens) must match one of them — rejecting tokens minted for a _different_ app client in the same pool. Off by default; see [Security](#security).
- `tokenUse` &mdash; **recommended.** Required `token_use` value(s): `'access'`, `'id'`, or an array. Rejects a token of the wrong type (e.g. an id token where an access token is expected). Off by default.
- `algorithms` &mdash; allowed signing algorithms: an array of JWA names (e.g. `['RS256']`) **or** a predicate `(alg, header) => boolean`. Default: `['RS256']`. Only asymmetric algorithms are verifiable (`RS256/384/512`, `PS256/384/512`, `ES256/384/512` — exported as `SUPPORTED_ALGORITHMS`); symmetric (`HS*`) and `none` are always rejected, so widening this list can never enable an algorithm-confusion attack.
- `validate` &mdash; optional `(payload, header) => boolean | Promise<boolean>` gate, run after all built-in checks pass. Return a falsy value (or throw) to reject. Use it for further claims such as `scope` or custom attributes.
- `throwOnError` &mdash; when `true`, the validator throws a `CognitoAuthError` (with a `.code` such as `'token_expired'` or `'wrong_audience'`) instead of resolving `null`, so you can tell _why_ a token failed. Default: `false`.
- `fetch` &mdash; custom `fetch` implementation. Default: the global `fetch`.
- `minRefreshInterval` &mdash; minimum milliseconds between per-issuer JWKS refreshes triggered by an unknown `kid` (key-rotation handling). Default: `30000`.
- `clockTolerance` &mdash; allowed clock skew in seconds for `exp` / `nbf`. Default: `0`.

The validator resolves to the decoded JWT payload when the algorithm policy, signature, issuer, `kid`, `exp` / `nbf`, `tokenUse`, `audience`, and `validate` hook all check out; otherwise `null` (or a thrown `CognitoAuthError` under `throwOnError`). JWKS keys are fetched lazily per issuer and refreshed automatically on key rotation; call `getUser.prime()` to pre-fetch them (e.g. to avoid first-request latency on a serverless cold start). The token header's `alg` is only ever checked against your `algorithms` policy — never used to choose how the token is verified.

## Security

Validation proves a token is genuinely from the pool — it does **not**, by itself, prove the token was issued _for your app_ or is the _right type_. For any pool with more than one app client, set both:

- **`audience`** — restrict to your app client id(s). Without it, a token minted for **any** app client in the same user pool (including a low-trust or attacker-controlled one) is accepted.
- **`tokenUse`** — APIs almost always want `'access'`; pin it so an **id** token (meant for the client, and which also carries `cognito:groups`) can't be used in its place.

```js
const getUser = makeGetUser({region: 'us-east-1', userPoolId: 'us-east-1_MY_USER_POOL'}, {audience: process.env.APP_CLIENT_ID, tokenUse: 'access'});
```

Tokens must be the **bare JWT** — there is no `Authorization: Bearer ` handling. If your source sends that header, strip the prefix first: `header.replace(/^Bearer\s+/i, '')`.

### Other OIDC providers

Cognito is the focus, but any OIDC issuer that publishes a JWKS works: pass `issuer` instead of `region` + `userPoolId`, and set `algorithms` to whatever it signs with.

```js
const getUser = makeGetUser({issuer: 'https://accounts.example.com'}, {algorithms: ['ES256', 'RS256'], validate: p => p.aud === 'my-api'});
```

### `utils/lazy-access-token`

Obtain an OAuth2 `client_credentials` access token (from a user-pool domain's `/oauth2/token`) on demand, cached until it nears expiry.

```js
import {createLazyAccessToken} from 'cognito-toolkit/utils/lazy-access-token';

const auth = createLazyAccessToken({
  url: 'https://auth.my-domain.com/oauth2/token',
  clientId: process.env.AUTH_CLIENT_ID,
  secret: process.env.AUTH_CLIENT_SECRET
});

const token = await auth.authorize(); // cached until shortly before expiry
// use token.access_token immediately; call authorize() again when you need it
```

- `authorize()` &mdash; returns a cached unexpired token or fetches a fresh one.
- `getToken()` &mdash; returns the current token (or `null`) without fetching.

### `utils/renewable-access-token`

Same token, but renewed proactively on a timer instead of on demand.

```js
import {createRenewableAccessToken} from 'cognito-toolkit/utils/renewable-access-token';

const auth = createRenewableAccessToken({
  url: 'https://auth.my-domain.com/oauth2/token',
  clientId: process.env.AUTH_CLIENT_ID,
  secret: process.env.AUTH_CLIENT_SECRET
});

await auth.retrieveToken(); // fetch once; auto-renews thereafter
const token = auth.getToken(); // always read the live token
// on shutdown:
auth.cancelRenewal(true);
```

- `retrieveToken()` &mdash; fetches a token and schedules a refresh shortly before expiry. The refresh timer is `unref`ed, so it never keeps the process alive on its own.
- `cancelRenewal(clearToken?)` &mdash; cancels the scheduled refresh; pass `true` to also drop the cached token.
- `getToken()` &mdash; returns the current token (or `null`). The renewal swaps it out over time, so always read it fresh.

Each holder keeps its own state — create one per credential set.

## Migrating from v1

- **Import.** v1 exported the function as the whole CommonJS module (`const makeGetUser = require('cognito-toolkit')`). v2 is ESM-only: `import makeGetUser from 'cognito-toolkit'`, or `const {makeGetUser} = require('cognito-toolkit')` from CommonJS. The `makeGetUser(pools)` arguments and return value are unchanged.
- **Token utilities are now factories.** v1's module-level `setCredentials()` / `authorize()` / `getToken()` becomes `createLazyAccessToken({url, clientId, secret})`; v1's `retrieveToken(url, id, secret)` / `cancelRenewal()` / `getToken()` becomes `createRenewableAccessToken({url, clientId, secret})`. This lets you hold more than one credential set per process.
- **Dependencies removed.** `jsonwebtoken`, `jwk-to-pem`, and `debug` are gone — verification now uses Node's `crypto`, and logging uses `NODE_DEBUG=cognito-toolkit`.

## Release notes

- **2.0.0** _Zero-dependency, ESM-only rewrite. Verification on Node built-ins (`crypto` + `fetch`); configurable algorithm policy (default RS256, asymmetric-only); `audience` / `tokenUse` / `validate` claim checks; `throwOnError` with typed `CognitoAuthError`; per-issuer JWKS with automatic rotation refresh + `prime()`; non-Cognito OIDC support; token utilities are now per-instance factories._
- 1.0.6 _Updated dependencies._
- 1.0.5 _Updated dependencies._
- 1.0.4 _Updated dependencies._
- 1.0.3 _Updated dependencies._
- 1.0.2 _Updated dependencies._
- 1.0.1 _Added support for multiple pools._
- 1.0.0 _The initial public release._

## License

[The 3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause)
