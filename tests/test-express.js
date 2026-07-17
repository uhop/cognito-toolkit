import http from 'node:http';
import test from 'tape-six';
import express from 'express';

import {CognitoJwtVerifier} from 'cognito-toolkit';
import {makeAuth} from 'cognito-toolkit/express';
import {makeKey, signWith} from './helpers/mock-cognito.js';

const userPoolId = 'us-east-1_EXPRESS';
const issuer = `https://cognito-idp.us-east-1.amazonaws.com/${userPoolId}`;
const clientId = 'express-client';

const key = makeKey(`${userPoolId}-key-1`);
const verifier = CognitoJwtVerifier.create({userPoolId, clientId, tokenUse: 'access'});
verifier.cacheJwks({keys: [key.jwk]});

const sign = (opts = {}) => signWith(key, {issuer, ...opts, claims: {client_id: clientId, ...opts.claims}});

// A 5-line stand-in for cookie-parser, enough for the auth-cookie lookups.
const cookieShim = (req, res, next) => {
  req.cookies = Object.fromEntries(
    (req.headers.cookie || '')
      .split(';')
      .map(pair => pair.trim().split('='))
      .filter(pair => pair.length === 2)
  );
  next();
};

const startApp = auth => {
  const app = express();
  app.use(cookieShim);
  app.use(auth.getUser);
  app.get('/open', (req, res) => res.send('open'));
  app.get('/user', (req, res) => res.json(req.user || {}));
  app.get('/auth', auth.isAuthenticated, (req, res) => res.send('ok'));
  app.get('/writers', auth.hasGroup('writers'), (req, res) => res.send('ok'));
  app.get('/scoped', auth.hasScope('write'), (req, res) => res.send('ok'));
  app.get(
    '/custom',
    auth.isAllowed(async (req, groups, scopes) => groups.includes('vip') || scopes.includes('vip')),
    (req, res) => res.send('ok')
  );
  const server = http.createServer(app);
  return new Promise(resolve =>
    server.listen(0, '127.0.0.1', () => resolve({base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(r => server.close(r))}))
  );
};

test('express: anonymous vs authenticated flows', async t => {
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
  t.equal(user.sub, 'mock-sub', 'user lands on req');
  t.equal(user._token, token, 'raw token is attached');

  response = await fetch(`${base}/auth`, {headers: {cookie: 'auth=' + token}});
  t.equal(response.status, 200, 'cookie is a token source');

  await close();
});

test('express: group and scope guards', async t => {
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

test('express: auth-cookie refresh', async t => {
  const {base, close} = await startApp(makeAuth({verifier, setAuthCookieOptions: {}}));
  const token = sign();

  let response = await fetch(`${base}/user`, {headers: {authorization: token}});
  const cookie = response.headers.get('set-cookie');
  t.ok(cookie && cookie.startsWith('auth='), 'auth cookie is set from the header token');

  response = await fetch(`${base}/user`, {headers: {authorization: token, cookie: 'auth=' + token}});
  t.equal(response.headers.get('set-cookie'), null, 'no refresh when the cookie already matches');

  await close();
});

test('express: custom source and state property', async t => {
  const auth = makeAuth({verifier, source: req => req.get('x-token') || null, stateUserProperty: 'account'});
  const app = express();
  app.use(auth.getUser);
  app.get('/', auth.isAuthenticated, (req, res) => res.json({sub: req.account.sub}));
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  t.equal((await fetch(base, {headers: {authorization: sign()}})).status, 401, 'default sources are replaced');
  const response = await fetch(base, {headers: {'x-token': sign()}});
  t.equal(response.status, 200, 'custom source is honored');
  t.equal((await response.json()).sub, 'mock-sub', 'custom state property carries the user');

  await new Promise(resolve => server.close(resolve));
});
