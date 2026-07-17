# `cognito-toolkit` [![NPM version][npm-img]][npm-url]

[npm-img]: https://img.shields.io/npm/v/cognito-toolkit.svg
[npm-url]: https://npmjs.org/package/cognito-toolkit
[aws-jwt-verify]: https://github.com/awslabs/aws-jwt-verify

[AWS Cognito](https://aws.amazon.com/cognito/) authentication & authorization for web apps: a middleware family for **Koa**, **Express**, **Fetch-style servers** (Bun, Deno, Cloudflare Workers, …), and **AWS Lambda** with route guards and an auth-cookie convenience, built on AWS's official [aws-jwt-verify] verifier, plus utilities for obtaining machine-to-machine (`client_credentials`) access tokens. ESM-only, one runtime dependency ([aws-jwt-verify], itself dependency-free).

The port family mirrors [dynamodb-toolkit](https://github.com/uhop/dynamodb-toolkit)'s adapters (`./koa`, `./express`, `./fetch`, `./lambda`), so the two toolkits compose without glue — e.g. `auth.isAuthenticated(createFetchAdapter(adapter))`.

> **v3 is a breaking reshape.** The homegrown verifier of 1.x is retired — token verification is delegated to [aws-jwt-verify], AWS's own zero-dependency verifier. The sister packages [koa-cognito-middleware](https://github.com/uhop/koa-cognito-middleware) and [cognito-express-middleware](https://github.com/uhop/cognito-express-middleware) moved here as the subpath exports `cognito-toolkit/koa` and `cognito-toolkit/express`; the standalone packages are frozen re-exports. See [Migrating](#migrating).

## Install

```sh
npm install cognito-toolkit
```

Requires Node 20+ (also runs on the latest Bun and Deno). ESM-only; CommonJS consumers load it via `require(esm)` (Node 20.19+ / 22.12+) and the named exports:

```js
const {makeGetUser, CognitoJwtVerifier} = require('cognito-toolkit');
const {makeAuth} = require('cognito-toolkit/koa'); // or /express, /fetch, /lambda
```

## Usage

### Koa

```js
import Koa from 'koa';
import Router from 'koa-router';
import {CognitoJwtVerifier} from 'cognito-toolkit';
import {makeAuth} from 'cognito-toolkit/koa';

// configure verification on the verifier — pools, app clients, token type
const verifier = CognitoJwtVerifier.create({
  userPoolId: 'us-east-1_MY_USER_POOL',
  clientId: 'my-app-client-id',
  tokenUse: 'access'
});

const auth = makeAuth({verifier});

const app = new Koa();
app.use(auth.getUser); // ctx.state.user = decoded payload or null

const router = new Router();
router.get('/a', ctx => (ctx.body = 'all allowed'));
router.get('/b', auth.isAuthenticated, ctx => (ctx.body = 'all authenticated'));
router.post('/c', auth.hasGroup('user-type/writers'), ctx => (ctx.body = 'only the writers group'));
router.post('/d', auth.hasScope('writers'), ctx => (ctx.body = 'only with a writers scope'));
app.use(router.routes()).use(router.allowedMethods());
```

### Express

```js
import express from 'express';
import cookieParser from 'cookie-parser';
import {CognitoJwtVerifier} from 'cognito-toolkit';
import {makeAuth} from 'cognito-toolkit/express';

const verifier = CognitoJwtVerifier.create({
  userPoolId: 'us-east-1_MY_USER_POOL',
  clientId: 'my-app-client-id',
  tokenUse: 'access'
});

const auth = makeAuth({verifier});

const app = express();
app.use(cookieParser()); // only needed for the auth-cookie features
app.use(auth.getUser); // req.user = decoded payload or null

app.get('/a', (req, res) => res.send('all allowed'));
app.get('/b', auth.isAuthenticated, (req, res) => res.send('all authenticated'));
app.post('/c', auth.hasGroup('user-type/writers'), (req, res) => res.send('only the writers group'));
app.post('/d', auth.hasScope('writers'), (req, res) => res.send('only with a writers scope'));
```

### Fetch-style servers (Bun, Deno, Cloudflare Workers, …)

Requests are immutable in the Fetch world, so there is no state property: guards **wrap handlers**, and `getUser(request)` is a memoized lookup — one verification per request no matter how often it's called. Extra server args (Bun's `server`, Deno's `info`, Cloudflare's `env`/`ctx`) flow through untouched.

```js
import {CognitoJwtVerifier} from 'cognito-toolkit';
import {makeAuth} from 'cognito-toolkit/fetch';

const verifier = CognitoJwtVerifier.create({userPoolId: 'us-east-1_MY_USER_POOL', clientId: 'my-app-client-id', tokenUse: 'access'});
const auth = makeAuth({verifier});

export default {
  fetch: auth.isAuthenticated(async request => {
    const user = await auth.getUser(request); // memoized — already verified by the guard
    return Response.json(user);
  })
};

// per-route guards wrap individual handlers:
const writers = auth.hasGroup('writers')(async request => new Response('ok'));
```

### AWS Lambda

Same wrapper model over Lambda events — API Gateway v1 and v2, Function URLs, and ALB event shapes are auto-detected (headers case-insensitively, v2 `cookies` array, ALB multi-value mode mirrored on responses).

```js
import {CognitoJwtVerifier} from 'cognito-toolkit';
import {makeAuth} from 'cognito-toolkit/lambda';

const verifier = CognitoJwtVerifier.create({userPoolId: 'us-east-1_MY_USER_POOL', clientId: 'my-app-client-id', tokenUse: 'access'});
const auth = makeAuth({verifier});

export const handler = auth.hasGroup('admins')(async (event, context) => ({statusCode: 200, body: 'ok'}));
```

> Behind API Gateway proper, prefer the built-in [Cognito / JWT authorizer](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html) — it rejects bad tokens without invoking your function. This port's niche is **Function URLs** (whose only auth options are IAM or none), **ALB** targets (pair it with aws-jwt-verify's `AlbJwtVerifier` when the ALB's `authenticate-cognito` action forwards `x-amzn-oidc-data`), and local-debug bridges.

### Framework-free

```js
import {makeGetUser, CognitoJwtVerifier} from 'cognito-toolkit';

const verifier = CognitoJwtVerifier.create({userPoolId: 'us-east-1_MY_USER_POOL', clientId: 'my-app-client-id', tokenUse: 'access'});
const getUser = makeGetUser(verifier);

const user = await getUser(tokenFromAnywhere); // decoded payload or null — never throws on a bad token
```

A rule of thumb for custom validators: an [isAllowed](#the-middleware-bundle) rule covers per-route logic; anything about the _token itself_ (audience, token use, extra claim checks) belongs on the verifier — see the [aws-jwt-verify] documentation for `customJwtCheck`, multi-pool setups, and the generic `JwtVerifier` for non-Cognito OIDC issuers. Both verifier classes are re-exported here for convenience.

Enable debug logging with the `NODE_DEBUG=cognito-toolkit` environment variable.

Full docs: this README plus the [wiki](https://github.com/uhop/cognito-toolkit/wiki) — [browse](https://github.com/uhop/cognito-toolkit/wiki/Home) or [search it](https://uhop.github.io/wiki-search/app/?wiki=uhop/cognito-toolkit).

## API

### `makeAuth(options)` — `cognito-toolkit/{koa,express,fetch,lambda}`

Builds a middleware bundle bound to one verifier and one options set. There are no module-level singletons — create as many bundles as you need. Options (shared across all four ports; Koa/Express semantics shown, Fetch/Lambda differences below):

- `verifier` — **required.** An [aws-jwt-verify] verifier (`CognitoJwtVerifier` / `JwtVerifier`), or anything with an async `verify(token)` that resolves to a payload and throws on an invalid token.
- `authHeader` — header carrying the **bare** token (no `Bearer` stripping — see [Security](#security)). A falsy value disables the header source. Default: `'Authorization'`.
- `authCookie` — cookie carrying the token; also the cookie written by the auth-cookie helpers. A falsy value disables both. Default: `'auth'`. (Express reads it from `req.cookies` — add [cookie-parser](https://www.npmjs.com/package/cookie-parser).)
- `source` — custom token source: `ctx => token` (Koa) / `req => token` (Express). Overrides the header / cookie lookups.
- `setAuthCookieOptions` — when set (an object of cookie options, `{}` is fine), every authenticated request refreshes the auth cookie automatically.
- `stateUserProperty` — where the user lands: `ctx.state[prop]` (Koa) / `req[prop]` (Express). Default: `'user'`.
- `throwOnError` — verification failures throw (as [aws-jwt-verify] error classes) instead of yielding an anonymous request. Default: `false`.

### The middleware bundle

- `getUser` — authenticates every request: the decoded payload (or `null`) is placed on `ctx.state.user` / `req.user` (see `stateUserProperty`). An authenticated user additionally carries `_token` (the raw token) and a bound `setAuthCookie` method.
- `isAuthenticated` — guard: 401 unless a user is present.
- `hasGroup(group)` — guard: 401 without a user, 403 unless the `cognito:groups` claim contains `group`.
- `hasScope(scope)` — guard: 401 without a user, 403 unless the space-separated `scope` claim contains `scope`.
- `isAllowed(validator)` — guard with a custom async rule `(ctx | req, groups, scopes) => boolean`; a falsy result yields 401 (anonymous) or 403 (authenticated).
- `setAuthCookie(ctx, options?)` / `setAuthCookie(req, res, options?)` — manually persist the current user's token into the auth cookie (skipped when the cookie already holds it). The cookie expires with the token; the domain defaults to the request's hostname.
- `stateUserProperty` — the resolved property name (for generic code).

The auth cookie enables a "login once" flow: authenticate via a header once (e.g. after an OAuth2 redirect), persist the token as a cookie, and let subsequent requests authenticate from the cookie automatically.

#### Fetch and Lambda differences

Requests/events are not decorated in these ports (Fetch `Request`s are immutable; Lambda events stay pristine), so the bundle shape shifts:

- No `stateUserProperty` — `getUser(request | event)` is a **memoized async lookup** instead of a middleware: guards and handlers share one verification per request.
- Guards **wrap handlers** (`auth.hasGroup('g')(handler)`) rather than chaining; denials are a `Response` (Fetch) or a result envelope like `{statusCode: 401}` (Lambda, mirroring ALB multi-value header mode when the trigger uses it).
- The automatic auth-cookie refresh applies to responses passing through guards; `setAuthCookie` is async and **returns** the response/result to use (Fetch may clone an immutable response; Lambda picks the shape — v2 `cookies` array, v1/ALB headers). Cookies are serialized in-house: `Path=/` and `HttpOnly` by default, `Domain` from the request hostname.

### `makeGetUser(verifier, options?)`

The framework-free core (default export): wraps a verifier into `token => Promise<payload | null>`. An absent token or a failed verification resolves to `null`; with `options.throwOnError` verification failures throw instead (an absent token still resolves to `null`). The returned function carries `prime()` — pre-fetches the verifier's JWKS (e.g. to avoid first-request latency on a serverless cold start; maps to the verifier's `hydrate()`).

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

- `authorize()` — returns a cached unexpired token or fetches a fresh one.
- `getToken()` — returns the current token (or `null`) without fetching.

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

- `retrieveToken()` — fetches a token and schedules a refresh shortly before expiry. The refresh timer is `unref`ed, so it never keeps the process alive on its own.
- `cancelRenewal(clearToken?)` — cancels the scheduled refresh; pass `true` to also drop the cached token.
- `getToken()` — returns the current token (or `null`). The renewal swaps it out over time, so always read it fresh.

Each holder keeps its own state — create one per credential set.

## TypeScript

The package ships hand-written `.d.ts` sidecars — no build step, no separate `@types` package. The middleware typings use real framework types (`@types/koa`, `@types/express`, `@types/aws-lambda`), which TypeScript consumers of those ports typically already have; the Fetch port needs only the standard `Request` / `Response` globals. The payload type flows from the verifier: `makeGetUser` and `makeAuth` are generic over it (defaulting to aws-jwt-verify's `JwtPayload`), and anything satisfying `TokenVerifier<P>` — an object with an async, throwing `verify(jwt)` — types through, including hand-rolled test stand-ins.

## Security

Verification is [aws-jwt-verify]'s job — algorithm policy, signature, issuer, expiry, and claim checks are all theirs (and battle-tested). Two knobs deserve emphasis because they are **on the verifier**, not on this package:

- **`clientId`** — restrict to your app client id(s). Without it, a token minted for **any** app client in the same user pool (including a low-trust one) is accepted.
- **`tokenUse`** — APIs almost always want `'access'`; pin it so an **id** token (meant for the client) can't be used in its place.

Tokens must be the **bare JWT** — there is no `Authorization: Bearer ` handling. If your clients send that prefix, strip it in a custom `source`:

```js
const auth = makeAuth({verifier, source: ctx => (ctx.headers.authorization || '').replace(/^Bearer\s+/i, '') || null});
```

## Migrating

### From `koa-cognito-middleware` / `cognito-express-middleware` 1.x

The features are all here; the wiring changed:

- **Import** — `import {makeAuth} from 'cognito-toolkit/koa'` (or `/express`) instead of requiring the standalone package.
- **Pool options → a verifier.** `getUser({region, userPoolId})` becomes `makeAuth({verifier: CognitoJwtVerifier.create({userPoolId, clientId, tokenUse})})` — note that `clientId` is required by aws-jwt-verify (pass `null` to explicitly opt out) and that pinning `tokenUse` is now first-class.
- **Guards moved off the function.** `getUser.isAuthenticated` / `hasGroup` / `hasScope` / `isAllowed` and `getUser.stateUserProperty` were statics shared by every consumer of the module; they are now members of the per-instance bundle returned by `makeAuth` — same names, same semantics, no cross-app coupling.
- The auth-cookie behavior (`authCookie`, `setAuthCookieOptions`, `user.setAuthCookie`) is preserved. The cookie domain now defaults to the request **hostname** — the old `host` default broke on Express 5, which keeps the port on `req.host`.

### From `cognito-toolkit` 1.x

1.x exported `makeGetUser(pools, options?)` with a homegrown verifier behind it. In v3 you build the verifier yourself and hand it over:

```js
// 1.x
const getUser = makeGetUser({region: 'us-east-1', userPoolId: 'us-east-1_X'}, {audience: 'client', tokenUse: 'access'});
// 3.x
const getUser = makeGetUser(CognitoJwtVerifier.create({userPoolId: 'us-east-1_X', clientId: 'client', tokenUse: 'access'}));
```

- Pool lists map to `CognitoJwtVerifier.create([...])`; non-Cognito OIDC issuers map to `JwtVerifier.create({issuer, audience, jwksUri?})`.
- 1.x options map onto verifier properties: `audience` → `clientId`, `validate` → `customJwtCheck`, `clockTolerance` → `graceSeconds`; `algorithms` policy and JWKS rotation handling are aws-jwt-verify internals now.
- `throwOnError` remains, but throws aws-jwt-verify error classes (`aws-jwt-verify/error`) instead of `CognitoAuthError`.
- The `utils/` token helpers are unchanged since the 2.x factories: module-level `setCredentials()` / `authorize()` / `getToken()` of 1.x became `createLazyAccessToken` / `createRenewableAccessToken` instances.
- Version 2.0.0 was a zero-dependency rewrite of the verifier that was never published — AWS's [aws-jwt-verify] covers that ground, which is exactly why v3 delegates to it.

## Release notes

Details per release live in the wiki's [Release notes](https://github.com/uhop/cognito-toolkit/wiki/Release-notes).

- **3.0.0** _Breaking reshape: verification delegated to AWS's [aws-jwt-verify]; the Koa & Express middlewares absorbed as `cognito-toolkit/koa` / `cognito-toolkit/express` with per-instance `makeAuth` bundles._
- **2.0.0** _Zero-dependency rewrite of the 1.x verifier — never published; superseded by 3.0.0._
- 1.0.6 _Updated dependencies._
- 1.0.5 _Updated dependencies._
- 1.0.4 _Updated dependencies._
- 1.0.3 _Updated dependencies._
- 1.0.2 _Updated dependencies._
- 1.0.1 _Added support for multiple pools._
- 1.0.0 _The initial public release._

## License

[The 3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause)
