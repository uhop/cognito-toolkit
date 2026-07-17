// CommonJS smoke test — demonstrates cognito-toolkit is usable from .cjs
// consumers via `require(esm)` (Node 20.19+ / 22.12+). CJS reaches the toolkit
// through the named export, never `.default`.

const {test} = require('tape-six');
const {makeGetUser, CognitoJwtVerifier} = require('cognito-toolkit');
const {makeAuth: makeKoaAuth} = require('cognito-toolkit/koa');
const {makeAuth: makeExpressAuth} = require('cognito-toolkit/express');
const {makeAuth: makeFetchAuth} = require('cognito-toolkit/fetch');
const {makeAuth: makeLambdaAuth} = require('cognito-toolkit/lambda');
const {createLazyAccessToken} = require('cognito-toolkit/utils/lazy-access-token');
const {createRenewableAccessToken} = require('cognito-toolkit/utils/renewable-access-token');

test('cjs: named exports resolve via require()', t => {
  t.equal(typeof makeGetUser, 'function', 'makeGetUser');
  t.equal(typeof CognitoJwtVerifier, 'function', 'CognitoJwtVerifier');
  t.equal(typeof makeKoaAuth, 'function', 'koa makeAuth');
  t.equal(typeof makeExpressAuth, 'function', 'express makeAuth');
  t.equal(typeof makeFetchAuth, 'function', 'fetch makeAuth');
  t.equal(typeof makeLambdaAuth, 'function', 'lambda makeAuth');
  t.equal(typeof createLazyAccessToken, 'function', 'createLazyAccessToken');
  t.equal(typeof createRenewableAccessToken, 'function', 'createRenewableAccessToken');
});

test('cjs: makeGetUser builds a validator', t => {
  const getUser = makeGetUser({verify: async () => ({})});
  t.equal(typeof getUser, 'function', 'returns a validator');
  t.throws(() => makeGetUser({}), 'still validates the verifier');
});
