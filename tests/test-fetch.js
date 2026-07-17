import test from 'tape-six';

import {CognitoJwtVerifier} from 'cognito-toolkit';
import {makeAuth} from 'cognito-toolkit/fetch';
import {makeKey, signWith} from './helpers/mock-cognito.js';

const userPoolId = 'us-east-1_FETCH';
const issuer = `https://cognito-idp.us-east-1.amazonaws.com/${userPoolId}`;
const clientId = 'fetch-client';

const key = makeKey(`${userPoolId}-key-1`);
const verifier = CognitoJwtVerifier.create({userPoolId, clientId, tokenUse: 'access'});
verifier.cacheJwks({keys: [key.jwk]});

const sign = (opts = {}) => signWith(key, {issuer, ...opts, claims: {client_id: clientId, ...opts.claims}});

const ok = async (request, ...rest) => new Response(JSON.stringify({rest}), {status: 200});

test('fetch: getUser resolves users and memoizes per request', async t => {
  let verified = 0;
  const counting = {
    verify: async token => (++verified, {sub: 'counted', token, exp: Math.floor(Date.now() / 1000) + 3600})
  };
  const auth = makeAuth({verifier: counting});
  const request = new Request('http://localhost/x', {headers: {authorization: 'opaque'}});

  const user = await auth.getUser(request);
  t.equal(user?.sub, 'counted', 'user resolved');
  t.equal(user?._token, 'opaque', 'raw token attached');
  await auth.getUser(request);
  t.equal(verified, 1, 'second lookup reuses the memoized verification');

  t.equal(await auth.getUser(new Request('http://localhost/x')), null, 'anonymous request resolves null');
});

test('fetch: isAuthenticated wraps handlers', async t => {
  const auth = makeAuth({verifier});
  const handler = auth.isAuthenticated(ok);

  let response = await handler(new Request('http://localhost/'));
  t.equal(response.status, 401, 'anonymous → 401');

  response = await handler(new Request('http://localhost/', {headers: {authorization: sign()}}), 'extra');
  t.equal(response.status, 200, 'authenticated → handler runs');
  t.deepEqual((await response.json()).rest, ['extra'], 'extra server args flow through');

  response = await handler(new Request('http://localhost/', {headers: {cookie: 'auth=' + sign()}}));
  t.equal(response.status, 200, 'cookie is a token source');
});

test('fetch: group and scope guards', async t => {
  const auth = makeAuth({verifier});
  const writers = auth.hasGroup('writers')(ok);
  const scoped = auth.hasScope('write')(ok);
  const custom = auth.isAllowed(async (request, groups, scopes) => groups.includes('vip') || scopes.includes('vip'))(ok);

  const plain = sign();
  const writer = sign({claims: {'cognito:groups': ['writers'], scope: 'read write'}});
  const vip = sign({claims: {scope: 'vip'}});
  const withToken = token => new Request('http://localhost/', token ? {headers: {authorization: token}} : undefined);

  t.equal((await writers(withToken())).status, 401, 'group guard: anonymous → 401');
  t.equal((await writers(withToken(plain))).status, 403, 'group guard: no group → 403');
  t.equal((await writers(withToken(writer))).status, 200, 'group guard: member → 200');

  t.equal((await scoped(withToken(plain))).status, 403, 'scope guard: no scope → 403');
  t.equal((await scoped(withToken(writer))).status, 200, 'scope guard: scoped → 200');

  t.equal((await custom(withToken())).status, 401, 'isAllowed: anonymous → 401');
  t.equal((await custom(withToken(plain))).status, 403, 'isAllowed: denied → 403');
  t.equal((await custom(withToken(vip))).status, 200, 'isAllowed: allowed → 200');
});

test('fetch: auth-cookie refresh', async t => {
  const auth = makeAuth({verifier, setAuthCookieOptions: {}});
  const handler = auth.isAuthenticated(ok);
  const token = sign();

  let response = await handler(new Request('http://localhost/', {headers: {authorization: token}}));
  const cookie = response.headers.get('set-cookie');
  t.ok(cookie && cookie.startsWith('auth='), 'auth cookie is set from the header token');
  t.ok(cookie && cookie.includes('HttpOnly'), 'HttpOnly by default');

  response = await handler(new Request('http://localhost/', {headers: {authorization: token, cookie: 'auth=' + token}}));
  t.equal(response.headers.get('set-cookie'), null, 'no refresh when the cookie already matches');
});

test('fetch: manual setAuthCookie', async t => {
  const auth = makeAuth({verifier});
  const token = sign();
  const request = new Request('http://localhost/', {headers: {authorization: token}});

  const response = await auth.setAuthCookie(request, new Response('body'), {secure: true});
  const cookie = response.headers.get('set-cookie');
  t.ok(cookie && cookie.startsWith('auth='), 'cookie set');
  t.ok(cookie && cookie.includes('Secure'), 'options honored');

  const unchanged = await auth.setAuthCookie(new Request('http://localhost/'), new Response('body'));
  t.equal(unchanged.headers.get('set-cookie'), null, 'anonymous request sets nothing');
});

test('fetch: custom source', async t => {
  const auth = makeAuth({verifier, source: request => request.headers.get('x-token')});
  const handler = auth.isAuthenticated(ok);

  t.equal((await handler(new Request('http://localhost/', {headers: {authorization: sign()}}))).status, 401, 'default sources are replaced');
  t.equal((await handler(new Request('http://localhost/', {headers: {'x-token': sign()}}))).status, 200, 'custom source is honored');
});
