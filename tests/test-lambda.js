import test from 'tape-six';

import {CognitoJwtVerifier} from 'cognito-toolkit';
import {makeAuth} from 'cognito-toolkit/lambda';
import {makeKey, signWith} from './helpers/mock-cognito.js';

const userPoolId = 'us-east-1_LAMBDA';
const issuer = `https://cognito-idp.us-east-1.amazonaws.com/${userPoolId}`;
const clientId = 'lambda-client';

const key = makeKey(`${userPoolId}-key-1`);
const verifier = CognitoJwtVerifier.create({userPoolId, clientId, tokenUse: 'access'});
verifier.cacheJwks({keys: [key.jwk]});

const sign = (opts = {}) => signWith(key, {issuer, ...opts, claims: {client_id: clientId, ...opts.claims}});

const v1Event = headers => ({httpMethod: 'GET', path: '/x', headers});
const v2Event = (headers, cookies) => ({
  version: '2.0',
  rawPath: '/x',
  headers,
  ...(cookies ? {cookies} : {}),
  requestContext: {http: {method: 'GET'}, domainName: 'api.example.com'}
});
const albMultiEvent = multiValueHeaders => ({
  httpMethod: 'GET',
  path: '/x',
  headers: null,
  multiValueHeaders,
  requestContext: {elb: {targetGroupArn: 'arn:aws:...'}}
});

const ok = async (event, ...rest) => ({statusCode: 200, body: JSON.stringify({rest})});

test('lambda: getUser resolves users across event shapes and memoizes', async t => {
  const auth = makeAuth({verifier});
  const token = sign();

  let user = await auth.getUser(v1Event({Authorization: token}));
  t.equal(user?.sub, 'mock-sub', 'v1 header (as-sent casing)');
  t.equal(user?._token, token, 'raw token attached');

  user = await auth.getUser(v2Event({authorization: token}));
  t.equal(user?.sub, 'mock-sub', 'v2 header (lowercased)');

  user = await auth.getUser(v2Event({}, ['other=1', 'auth=' + token]));
  t.equal(user?.sub, 'mock-sub', 'v2 cookies array');

  user = await auth.getUser(albMultiEvent({Authorization: [token]}));
  t.equal(user?.sub, 'mock-sub', 'ALB multi-value headers');

  t.equal(await auth.getUser(v1Event({})), null, 'anonymous event resolves null');

  let verified = 0;
  const counting = makeAuth({verifier: {verify: async () => (++verified, {sub: 'x', exp: 0})}});
  const event = v1Event({Authorization: 'opaque'});
  await counting.getUser(event);
  await counting.getUser(event);
  t.equal(verified, 1, 'second lookup reuses the memoized verification');
});

test('lambda: guards return Lambda result envelopes', async t => {
  const auth = makeAuth({verifier});
  const guarded = auth.isAuthenticated(ok);
  const writers = auth.hasGroup('writers')(ok);
  const custom = auth.isAllowed(async (event, groups, scopes) => scopes.includes('vip'))(ok);

  const plain = sign();
  const writer = sign({claims: {'cognito:groups': ['writers'], scope: 'read write'}});
  const vip = sign({claims: {scope: 'vip'}});

  let result = await guarded(v1Event({}));
  t.equal(result.statusCode, 401, 'anonymous → 401');
  t.equal(result.multiValueHeaders, undefined, 'plain v1 deny has no multiValueHeaders');

  result = await guarded(v1Event({Authorization: plain}), {functionName: 'f'});
  t.equal(result.statusCode, 200, 'authenticated → handler runs');
  t.equal(JSON.parse(result.body).rest.length, 1, 'context flows through');

  t.equal((await writers(v1Event({Authorization: plain}))).statusCode, 403, 'group guard: no group → 403');
  t.equal((await writers(v1Event({Authorization: writer}))).statusCode, 200, 'group guard: member → 200');
  t.equal((await auth.hasScope('write')(ok)(v1Event({Authorization: writer}))).statusCode, 200, 'scope guard: scoped → 200');

  t.equal((await custom(v1Event({}))).statusCode, 401, 'isAllowed: anonymous → 401');
  t.equal((await custom(v1Event({Authorization: plain}))).statusCode, 403, 'isAllowed: denied → 403');
  t.equal((await custom(v1Event({Authorization: vip}))).statusCode, 200, 'isAllowed: allowed → 200');

  result = await auth.isAuthenticated(ok)(albMultiEvent({}));
  t.equal(result.statusCode, 401, 'ALB multi-value deny');
  t.deepEqual(result.multiValueHeaders, {}, 'ALB multi-value deny mirrors the header mode');
});

test('lambda: auth-cookie refresh is event-shape-aware', async t => {
  const auth = makeAuth({verifier, setAuthCookieOptions: {}});
  const handler = auth.isAuthenticated(ok);
  const token = sign();

  let result = await handler(v2Event({authorization: token}));
  t.ok(result.cookies && result.cookies[0].startsWith('auth='), 'v2: cookie lands in the cookies array');
  t.ok(result.cookies[0].includes('Domain=api.example.com'), 'v2: domain from requestContext');

  result = await handler(v2Event({authorization: token}, ['auth=' + token]));
  t.equal(result.cookies, undefined, 'v2: no refresh when the cookie already matches');

  result = await handler(v1Event({Authorization: token, Host: 'api.example.com:8443'}));
  const cookie = result.headers && result.headers['Set-Cookie'];
  t.ok(cookie && cookie.startsWith('auth='), 'v1: cookie lands in headers');
  t.ok(cookie.includes('Domain=api.example.com'), 'v1: domain from Host header, port stripped');

  result = await handler(albMultiEvent({Authorization: [token]}));
  const multi = result.multiValueHeaders && result.multiValueHeaders['Set-Cookie'];
  t.ok(multi && multi[0].startsWith('auth='), 'ALB multi-value: cookie lands in multiValueHeaders');
});

test('lambda: manual setAuthCookie and custom source', async t => {
  const auth = makeAuth({verifier});
  const token = sign();

  const result = await auth.setAuthCookie(v2Event({authorization: token}), {statusCode: 204, body: ''});
  t.ok(result.cookies && result.cookies[0].startsWith('auth='), 'manual set on a v2 result');

  const custom = makeAuth({verifier, source: event => (event.headers && event.headers['x-token']) || null});
  t.equal((await custom.isAuthenticated(ok)(v1Event({Authorization: token}))).statusCode, 401, 'default sources are replaced');
  t.equal((await custom.isAuthenticated(ok)(v1Event({'x-token': token}))).statusCode, 200, 'custom source is honored');
});
