import test from 'tape-six';

import makeGetUser, {type GetUser, type PoolOptions, type CognitoUser} from 'cognito-toolkit';
import {createLazyAccessToken, type LazyAccessToken} from 'cognito-toolkit/utils/lazy-access-token';

test('typed: makeGetUser returns a GetUser', async t => {
  const pool: PoolOptions = {region: 'us-east-1', userPoolId: 'us-east-1_X'};
  const getUser: GetUser = makeGetUser(pool, {clockTolerance: 5});
  const user: CognitoUser | null = await getUser('not.a.token');
  t.equal(user, null, 'garbage rejected');
});

test('typed: createLazyAccessToken returns a holder', t => {
  const holder: LazyAccessToken = createLazyAccessToken({url: 'https://example/oauth2/token', clientId: 'id', secret: 's'});
  t.equal(typeof holder.authorize, 'function');
  t.equal(holder.getToken(), null);
});
