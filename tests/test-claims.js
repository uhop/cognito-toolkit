import test from 'tape-six';

import makeGetUser, {CognitoAuthError} from 'cognito-toolkit';

import {startMockCognito} from './helpers/mock-cognito.js';

test('audience: an id token must carry an allowed aud', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer}, {audience: 'app-client-1'});
  t.ok(await getUser(pool.sign({tokenUse: 'id', claims: {aud: 'app-client-1'}})), 'matching aud accepted');
  t.equal(await getUser(pool.sign({tokenUse: 'id', claims: {aud: 'other-client'}})), null, 'foreign aud rejected');
  t.equal(await getUser(pool.sign({tokenUse: 'id'})), null, 'missing aud rejected');
  await pool.close();
});

test('audience: an access token must carry an allowed client_id', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer}, {audience: ['app-client-1', 'app-client-2']});
  t.ok(await getUser(pool.sign({claims: {client_id: 'app-client-2'}})), 'matching client_id accepted (array allowlist)');
  t.equal(await getUser(pool.sign({claims: {client_id: 'rogue'}})), null, 'foreign client_id rejected');
  await pool.close();
});

test('tokenUse: only the configured token_use is accepted', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer}, {tokenUse: 'access'});
  t.ok(await getUser(pool.sign({tokenUse: 'access'})), 'access token accepted');
  t.equal(await getUser(pool.sign({tokenUse: 'id'})), null, 'id token rejected when access is required');
  await pool.close();
});

test('throwOnError: failures throw a typed CognitoAuthError with a code', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer}, {throwOnError: true, tokenUse: 'access', audience: 'app-1'});

  t.ok(await getUser(pool.sign({tokenUse: 'access', claims: {client_id: 'app-1'}})), 'valid token still resolves');

  const cases = [
    [pool.sign({expiresIn: -10, claims: {client_id: 'app-1'}}), 'token_expired'],
    [pool.sign({tokenUse: 'id', claims: {aud: 'app-1'}}), 'wrong_token_use'],
    [pool.sign({tokenUse: 'access', claims: {client_id: 'nope'}}), 'wrong_audience'],
    [pool.signForeign({claims: {client_id: 'app-1'}}), 'unknown_key'],
    ['not.a.jwt', 'malformed_token']
  ];
  for (const [token, code] of cases) {
    try {
      await getUser(token);
      t.fail(`expected ${code} to throw`);
    } catch (error) {
      t.ok(error instanceof CognitoAuthError, `${code}: is a CognitoAuthError`);
      t.equal(error.code, code, `${code}: correct code`);
    }
  }
  await pool.close();
});

test('throwOnError: false (default) still resolves null on failure', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer});
  t.equal(await getUser('not.a.jwt'), null, 'no throw by default');
  await pool.close();
});

test('prime: pre-fetches the JWKS so the first verify needs no extra fetch', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer});
  t.equal(typeof getUser.prime, 'function', 'validator exposes prime()');

  await getUser.prime();
  t.equal(pool.jwksRequests(), 1, 'prime() fetched the JWKS once');

  t.ok(await getUser(pool.sign()), 'token verifies');
  t.equal(pool.jwksRequests(), 1, 'no additional JWKS fetch — key was already cached');
  await pool.close();
});
