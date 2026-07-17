import test from 'tape-six';

import makeGetUser, {makeGetUser as named, CognitoJwtVerifier, JwtVerifier} from 'cognito-toolkit';

test('smoke: default and named exports are the same function', t => {
  t.equal(typeof makeGetUser, 'function', 'default export');
  t.equal(makeGetUser, named, 'named mirror matches default');
  t.equal(typeof CognitoJwtVerifier, 'function', 'CognitoJwtVerifier re-export');
  t.equal(typeof JwtVerifier, 'function', 'JwtVerifier re-export');
});

test('smoke: middleware sub-exports resolve', async t => {
  const koa = await import('cognito-toolkit/koa');
  t.equal(typeof koa.makeAuth, 'function', 'koa named');
  t.equal(koa.default, koa.makeAuth, 'koa default matches named');

  const express = await import('cognito-toolkit/express');
  t.equal(typeof express.makeAuth, 'function', 'express named');
  t.equal(express.default, express.makeAuth, 'express default matches named');

  const fetchPort = await import('cognito-toolkit/fetch');
  t.equal(typeof fetchPort.makeAuth, 'function', 'fetch named');
  t.equal(fetchPort.default, fetchPort.makeAuth, 'fetch default matches named');

  const lambda = await import('cognito-toolkit/lambda');
  t.equal(typeof lambda.makeAuth, 'function', 'lambda named');
  t.equal(lambda.default, lambda.makeAuth, 'lambda default matches named');
});

test('smoke: util sub-exports resolve', async t => {
  const lazy = await import('cognito-toolkit/utils/lazy-access-token');
  t.equal(typeof lazy.default, 'function', 'lazy default');
  t.equal(typeof lazy.createLazyAccessToken, 'function', 'lazy named');

  const renew = await import('cognito-toolkit/utils/renewable-access-token');
  t.equal(typeof renew.default, 'function', 'renewable default');
  t.equal(typeof renew.createRenewableAccessToken, 'function', 'renewable named');
});

test('smoke: makeGetUser validates the verifier', t => {
  t.throws(() => makeGetUser(), /verifier/, 'no verifier');
  t.throws(() => makeGetUser({}), /verifier/, 'not a verifier');

  const getUser = makeGetUser({verify: async () => ({})});
  t.equal(typeof getUser, 'function', 'returns a validator');
  t.equal(typeof getUser.prime, 'function', 'carries prime()');
});
