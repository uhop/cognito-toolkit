import http from 'node:http';
import test from 'tape-six';
import Koa from 'koa';

import {CognitoJwtVerifier} from 'cognito-toolkit';
import {makeAuth} from 'cognito-toolkit/koa';
import {makeKey, signWith} from './helpers/mock-cognito.js';

const userPoolId = 'us-east-1_KOA';
const issuer = `https://cognito-idp.us-east-1.amazonaws.com/${userPoolId}`;
const clientId = 'koa-client';

const key = makeKey(`${userPoolId}-key-1`);
const verifier = CognitoJwtVerifier.create({userPoolId, clientId, tokenUse: 'access'});
verifier.cacheJwks({keys: [key.jwk]});

const sign = (opts = {}) => signWith(key, {issuer, ...opts, claims: {client_id: clientId, ...opts.claims}});

const route =
  (path, ...mws) =>
  async (ctx, next) => {
    if (ctx.path !== path) return next();
    let i = 0;
    const run = () => {
      const mw = mws[i++];
      return mw ? mw(ctx, run) : Promise.resolve();
    };
    return run();
  };

const startApp = auth => {
  const app = new Koa();
  app.use(auth.getUser);
  app.use(route('/open', ctx => void (ctx.body = 'open')));
  app.use(route('/user', ctx => void (ctx.body = ctx.state.user || {})));
  app.use(route('/auth', auth.isAuthenticated, ctx => void (ctx.body = 'ok')));
  app.use(route('/writers', auth.hasGroup('writers'), ctx => void (ctx.body = 'ok')));
  app.use(route('/scoped', auth.hasScope('write'), ctx => void (ctx.body = 'ok')));
  app.use(
    route(
      '/custom',
      auth.isAllowed(async (ctx, groups, scopes) => groups.includes('vip') || scopes.includes('vip')),
      ctx => void (ctx.body = 'ok')
    )
  );
  const server = http.createServer(app.callback());
  return new Promise(resolve =>
    server.listen(0, '127.0.0.1', () => resolve({base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(r => server.close(r))}))
  );
};

test('koa: anonymous vs authenticated flows', async t => {
  const {base, close} = await startApp(makeAuth({verifier}));
  const token = sign();

  let response = await fetch(`${base}/open`);
  t.equal(response.status, 200, 'open route passes anonymously');

  response = await fetch(`${base}/auth`);
  t.equal(response.status, 401, 'guarded route rejects anonymously');

  response = await fetch(`${base}/auth`, {headers: {authorization: token}});
  t.equal(response.status, 200, 'guarded route passes with a token');

  response = await fetch(`${base}/user`, {headers: {authorization: token}});
  const user = await response.json();
  t.equal(user.sub, 'mock-sub', 'user lands on ctx.state');
  t.equal(user._token, token, 'raw token is attached');

  response = await fetch(`${base}/auth`, {headers: {cookie: 'auth=' + token}});
  t.equal(response.status, 200, 'cookie is a token source');

  await close();
});

test('koa: group and scope guards', async t => {
  const {base, close} = await startApp(makeAuth({verifier}));
  const plain = sign();
  const writer = sign({claims: {'cognito:groups': ['writers'], scope: 'read write'}});
  const vip = sign({claims: {scope: 'vip'}});

  t.equal((await fetch(`${base}/writers`)).status, 401, 'group guard: anonymous → 401');
  t.equal((await fetch(`${base}/writers`, {headers: {authorization: plain}})).status, 403, 'group guard: no group → 403');
  t.equal((await fetch(`${base}/writers`, {headers: {authorization: writer}})).status, 200, 'group guard: member → 200');

  t.equal((await fetch(`${base}/scoped`, {headers: {authorization: plain}})).status, 403, 'scope guard: no scope → 403');
  t.equal((await fetch(`${base}/scoped`, {headers: {authorization: writer}})).status, 200, 'scope guard: scoped → 200');

  t.equal((await fetch(`${base}/custom`)).status, 401, 'isAllowed: anonymous → 401');
  t.equal((await fetch(`${base}/custom`, {headers: {authorization: plain}})).status, 403, 'isAllowed: denied → 403');
  t.equal((await fetch(`${base}/custom`, {headers: {authorization: vip}})).status, 200, 'isAllowed: allowed → 200');

  await close();
});

test('koa: auth-cookie refresh', async t => {
  const {base, close} = await startApp(makeAuth({verifier, setAuthCookieOptions: {}}));
  const token = sign();

  let response = await fetch(`${base}/user`, {headers: {authorization: token}});
  const cookie = response.headers.get('set-cookie');
  t.ok(cookie && cookie.startsWith('auth='), 'auth cookie is set from the header token');

  response = await fetch(`${base}/user`, {headers: {authorization: token, cookie: 'auth=' + token}});
  t.equal(response.headers.get('set-cookie'), null, 'no refresh when the cookie already matches');

  await close();
});

test('koa: custom source and state property', async t => {
  const auth = makeAuth({verifier, source: ctx => ctx.headers['x-token'] || null, stateUserProperty: 'account'});
  const app = new Koa();
  app.use(auth.getUser);
  app.use(auth.isAuthenticated);
  app.use(ctx => void (ctx.body = {sub: ctx.state.account.sub}));
  const server = http.createServer(app.callback());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  t.equal((await fetch(base, {headers: {authorization: sign()}})).status, 401, 'default sources are replaced');
  const response = await fetch(base, {headers: {'x-token': sign()}});
  t.equal(response.status, 200, 'custom source is honored');
  t.equal((await response.json()).sub, 'mock-sub', 'custom state property carries the user');

  await new Promise(resolve => server.close(resolve));
});
