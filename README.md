# `cognito-toolkit`

[![Dependencies][deps-image]][deps-url]
[![devDependencies][dev-deps-image]][dev-deps-url]
[![NPM version][npm-image]][npm-url]

The [Koa](https://koajs.com/) middleware to authenticate and authorized users using [AWS Cognito](https://aws.amazon.com/cognito/)
[user pools](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html).
It validates a JWT token (either an id or access token) and populates `ctx.state.user` with its deciphered content.
Simple helpers are provided to make decisions on accessibility of API endpoints for a given user.

# Examples

```js
const Koa = require('koa');
const Router = require('koa-router');
const getUser = require('koa-cognito-middleware');

const {isAuthenticated, hasScope, hasGroup, isAllowed} = getUser;

const app = new Koa();

// run getUser() on every request
app.use(getUser({
  region: 'us-east-1',
  userPoolId: 'us-east-1_MY_USER_POOL'
}));

// populate router1 with custom authorization rules

const router1 = new Router();

router1.get('/a',
  async ctx => (ctx.body = 'all allowed'));
router1.get('/b', isAuthenticated,
  async ctx => (ctx.body = 'all authenticated'));
router1.post('/c', hasGroup('user-type/writers'),
  async ctx => (ctx.body = 'only a writers group'));
router1.post('/d', hasScope('writers'),
  async ctx => (ctx.body = 'only with a writers scope'));

app
  .use(router1.routes())
  .use(router1.allowedMethods());

// protect all routes with a single validator

const router2 = new Router();
// populate router2

const readMethods = {GET: 1, HEAD: 1, OPTIONS: 1};

const validator = async (ctx, groups, scopes) => {
  if (readMethods(ctx.method.toUpperCase()) === 1) return true;
  // only writers can use other methods (POST, PUT, PATCH, DELETE...)
  if (groups.some(g => g === 'user-type/writers')) return true;
  if (scopes.some(s => s === 'writers')) return true;
  return false;
};

app
  .use(isAllowed(validator))
  .use(router2.routes())
  .use(router2.allowedMethods());

// now all routes of router2 are protected by our validator
```

# How to install

```txt
npm install --save koa-cognito-middleware
# yarn add koa-cognito-middleware
```

# Documentation

All provided functions are explained below. See the examples above for usage patterns.

## `getUser(options)`

This is the main function directly returned from the module. It populates `ctx.state.user` with a decoded JWT token or assigns it to `null` (cannot positively authenticate).
Other helpers or a user's code uses it to authorize or reject the user for a given route.

It takes one argument `options`, which is an object with the following properties:

* `region` &mdash **required** string, which specifies an AWS region, such as `'us-east-1'`. Default: **none**.
* `userPoolId` &mdash **required** string, which specifies a user pool ID, such as `'us-east-1_MY_USER_POOL'`. Default: **none**.
* `source` &mdash; optional function or string. Default: `'Authorization'`.
  * If it is a string, it specifies an HTTP request header name. Its value should be a JWT token supplied by AWS Cognito (`id_token` or `access_token`).
  * If it is a function, it is called with `ctx` argument, and can inspect a request to produce a JWT token as a string.
    * Examples:
      ```js
      const getToken1 = ctx => ctx.headers['x-auth-header'];
      const getToken2 = ctx => ctx.cookies.get('auth-token');
      ```

This function should be used before any other helpers.

## `getUser.isAuthenticated`

This is a helper function, which checks if `ctx.state.user` is set. If not it rejects a request with 401 (unauthorized).

## `getUser.hasGroup(group)`

This is a helper function, which checks if `ctx.state.user` has `'cognito:groups'` array that includes a given group (as a string).
If not it rejects a request with 403 (forbidden) for valid users and 401 (unauthorized) for non-authenticated users.

## `getUser.hasScope(scope)`

This is a helper function, which checks if `ctx.state.user` has `'scope'` string that includes a given scope (as a string).
If not it rejects a request with 403 (forbidden) for valid users and 401 (unauthorized) for non-authenticated users.

## `getUser.isAllowed(validator)`

This is a helper function, which checks runs a validator. If not it rejects a request with 403 (forbidden) for valid users and 401 (unauthorized) for non-authenticated users.

`validator` is an asynchronous function, which is called with three parameters: the original `ctx`, `groups` and `scopes`.
The latter two parameters are arrays of strings listing `cognito:groups` and `scope` items respectively.
`validator` should return a truthy value, if a user is allowed to perform an action, and a falsy value otherwise.

## Utilities: `utils/lazyAccessToken`

It is a helper to retrieve an access token lazily on demand.

### `setCredentials(url, clientId, secret)`

This synchronous function sets credentials for future authentications. It takes a URL (usually in the form of *Cognito user pool DNS*`/oauth2/token`),
an app client ID and an app client secret (all as strings) and retrieves an access token
(see [TOKEN Endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html), the part on `client_credentials`).

### `getToken()`

This synchronous function returns the current token whatever it is. If it was not retrieved yet, it will return `null`.

### `authorize()`

This **asynchronous** function checks if there is an unexpired token and retrieves it, if required. It uses credentials set by `setCredentials()` (see above).
As a result it returns a token or `null`, if credentials were not set. After running this function the current token can be obtained with `getToken()` (see above).

Examples:

```js
const {setCredentials, authorize} = require('koa-cognito-middleware/utils/lazyAccessToken');

// ...

setCredentials(
  'https://auth.my-custom-domain/oauth2/token',
  process.env.AUTH_CLIENT_ID,
  process.env.AUTH_CLIENT_SECRET
);

// ...

const doIt = async () => {
  // every time we call it, it retrieves a token from a server
  const token = await authorize();
  // use the token immediately: it can be changed next time you need it
  const options = {
    protocol: 'https',
    hostname: 'api.my-custom-domain.com',
    path: '/items',
    method: 'GET',
    headers: {
      Accept: 'application/json',
      Authorization: token.access_token
    }
  };
  // do a call ...
};
```

## Utilities: `utils/renewableAccessToken`

It is a helper to retrieve an access token on demand, then renew it by a timer automatically.

### `retrieveToken(url, clientId, secret)`

This **asynchronous** function takes a URL (usually in the form of *Cognito user pool DNS*`/oauth2/token`), an app client ID and an app client secret (all as strings)
and retrieves an access token (see [TOKEN Endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html), the part on `client_credentials`).

Warning: the function always uses `https` protocol, which is a default for Cognito pools.

The function schedules itself to run when a token is about to expire. The exact algorithm is `expires_in` (defined in the token structure) minus 5 minutes.
If the result is negative, it will run in a half of `expires_in` time.

While the function resolves its return in a token structure, do not save it because it can be updated over time. Always use `getToken()` function (described below) before using a token.

Example:

```js
const {retrieveToken} = require('koa-cognito-middleware/utils/renewableAccessToken');

// ...

const doIt = async () => {
  // every time we call it, it retrieves a token from a server
  const token = await retrieveToken(
    'https://auth.my-custom-domain/oauth2/token',
    process.env.AUTH_CLIENT_ID,
    process.env.AUTH_CLIENT_SECRET
  );
  // use the token immediately: it can be changed next time you need it
  const options = {
    protocol: 'https',
    hostname: 'api.my-custom-domain.com',
    path: '/items',
    method: 'GET',
    headers: {
      Accept: 'application/json',
      Authorization: token.access_token
    }
  };
  // do a call ...
};
```

### `getToken()`

This synchronous function returns the current token whatever it is. If it was not retrieved yet, it will return `null`.

Example:

```js
// rewriting the previous example

const {retrieveToken, getToken} = require('koa-cognito-middleware/utils/renewableAccessToken');

const authorize = () => {
  // this function can be called multiple times
  // it calls the retrieveToken() only when necessary
  // and getToken() always returns the fresh token
  if (!getToken()) {
    return retrieveToken(
      'https://auth.my-custom-domain/oauth2/token',
      process.env.AUTH_CLIENT_ID,
      process.env.AUTH_CLIENT_SECRET
    );
  }
};

// ...

const doIt = async () => {
  await authorize(); // we can call it many times without taxing the auth system
  const token = getToken(); // totally safe to get a token like that
  // like in the previous example ...
};
```

# Versions

- 1.2.0 &mdash; *Added a utility to lazily retrieve an access token by client ID and a secret*
- 1.1.0 &mdash; *Added a utility to auto-retrieve an access token by client ID and a secret*
- 1.0.0 &mdash; *The initial public release*

# License

[The 3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause)

[npm-image]:       https://img.shields.io/npm/v/koa-cognito-middleware.svg
[npm-url]:         https://npmjs.org/package/koa-cognito-middleware
[deps-image]:      https://img.shields.io/david/uhop/koa-cognito-middleware.svg
[deps-url]:        https://david-dm.org/uhop/koa-cognito-middleware
[dev-deps-image]:  https://img.shields.io/david/dev/uhop/koa-cognito-middleware.svg
[dev-deps-url]:    https://david-dm.org/uhop/koa-cognito-middleware?type=dev
