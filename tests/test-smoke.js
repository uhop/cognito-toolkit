import test from 'tape-six';

import makeGetUser, {makeGetUser as named} from 'cognito-toolkit';

test('smoke: default and named exports are the same function', t => {
  t.equal(typeof makeGetUser, 'function', 'default export');
  t.equal(makeGetUser, named, 'named mirror matches default');
});

test('smoke: util sub-exports resolve', async t => {
  const lazy = await import('cognito-toolkit/utils/lazy-access-token');
  t.equal(typeof lazy.default, 'function', 'lazy default');
  t.equal(typeof lazy.createLazyAccessToken, 'function', 'lazy named');

  const renew = await import('cognito-toolkit/utils/renewable-access-token');
  t.equal(typeof renew.default, 'function', 'renewable default');
  t.equal(typeof renew.createRenewableAccessToken, 'function', 'renewable named');
});

test('smoke: makeGetUser validates required options', t => {
  t.throws(() => makeGetUser(), /Pool options should be specified/, 'no options');
  t.throws(() => makeGetUser({}), /Region should be specified/, 'missing region');
  t.throws(() => makeGetUser({region: 'us-east-1'}), /User pool ID should be specified/, 'missing pool id');

  const getUser = makeGetUser({region: 'us-east-1', userPoolId: 'us-east-1_X'});
  t.equal(typeof getUser, 'function', 'returns a validator');
});
