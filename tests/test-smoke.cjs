// CommonJS smoke test — demonstrates cognito-toolkit is usable from .cjs
// consumers via `require(esm)` (Node 20.19+ / 22.12+). CJS reaches the toolkit
// through the named export, never `.default`.

const {test} = require('tape-six');
const {makeGetUser} = require('cognito-toolkit');
const {createLazyAccessToken} = require('cognito-toolkit/utils/lazy-access-token');
const {createRenewableAccessToken} = require('cognito-toolkit/utils/renewable-access-token');

test('cjs: named exports resolve via require()', t => {
  t.equal(typeof makeGetUser, 'function', 'makeGetUser');
  t.equal(typeof createLazyAccessToken, 'function', 'createLazyAccessToken');
  t.equal(typeof createRenewableAccessToken, 'function', 'createRenewableAccessToken');
});

test('cjs: makeGetUser builds a validator', t => {
  const getUser = makeGetUser({region: 'us-east-1', userPoolId: 'us-east-1_X'});
  t.equal(typeof getUser, 'function', 'returns a validator');
  t.throws(() => makeGetUser({}), 'still validates options');
});
