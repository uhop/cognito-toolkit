import test from 'tape-six';

import makeGetUser from 'cognito-toolkit';

import {startMockCognito} from './helpers/mock-cognito.js';

const base64url = value => Buffer.from(JSON.stringify(value)).toString('base64url');

test('verify: a valid access token resolves to its payload', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer});
  const user = await getUser(pool.sign({claims: {'cognito:username': 'ada', 'cognito:groups': ['admin']}}));
  t.ok(user, 'token verified');
  t.equal(user.iss, pool.issuer, 'issuer claim preserved');
  t.equal(user['cognito:username'], 'ada', 'custom claim preserved');
  t.deepEqual(user['cognito:groups'], ['admin'], 'group claim preserved');
  await pool.close();
});

test('verify: an id token verifies too', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer});
  const user = await getUser(pool.sign({tokenUse: 'id', claims: {email: 'ada@example.com'}}));
  t.ok(user, 'id token verified');
  t.equal(user.token_use, 'id');
  await pool.close();
});

test('verify: region + userPoolId derives the Cognito issuer URL', async t => {
  const getUser = makeGetUser({region: 'us-east-1', userPoolId: 'us-east-1_AbCdef'});
  t.equal(typeof getUser, 'function', 'returns a validator');
  // No network here: a structurally invalid token is rejected before any fetch.
  t.equal(await getUser('not.a.real.token'), null, 'garbage rejected');
});

test('verify: an expired token is rejected', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer});
  t.equal(await getUser(pool.sign({expiresIn: -10})), null, 'expired → null');
  await pool.close();
});

test('verify: a not-yet-valid token (nbf) is rejected', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer});
  const future = Math.floor(Date.now() / 1000) + 3600;
  t.equal(await getUser(pool.sign({claims: {nbf: future}})), null, 'nbf in future → null');
  await pool.close();
});

test('verify: a wrong issuer is rejected', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer});
  t.equal(await getUser(pool.sign({claims: {iss: 'https://evil.example.com/pool'}})), null, 'foreign iss → null');
  await pool.close();
});

test('verify: an unknown kid (key not in JWKS) is rejected', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer});
  t.equal(await getUser(pool.signForeign()), null, 'unknown kid → null');
  await pool.close();
});

test('verify: a tampered payload is rejected', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer});
  const [header, , signature] = pool.sign().split('.');
  const forgedPayload = base64url({iss: pool.issuer, sub: 'attacker', exp: Math.floor(Date.now() / 1000) + 3600});
  t.equal(await getUser(`${header}.${forgedPayload}.${signature}`), null, 'signature mismatch → null');
  await pool.close();
});

test('verify: an unsigned alg:none token is rejected', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer});
  const header = base64url({alg: 'none', kid: 'key-1', typ: 'JWT'});
  const payload = base64url({iss: pool.issuer, sub: 'attacker', exp: Math.floor(Date.now() / 1000) + 3600});
  t.equal(await getUser(`${header}.${payload}.`), null, 'alg:none → null');
  await pool.close();
});

test('verify: rotated signing keys are picked up automatically', async t => {
  const pool = await startMockCognito();
  // minRefreshInterval: 0 so the rotation is observed immediately (the default
  // throttles refreshes to bound unknown-kid JWKS storms).
  const getUser = makeGetUser({issuer: pool.issuer}, {minRefreshInterval: 0});
  t.ok(await getUser(pool.sign()), 'original key works (and is cached)');
  pool.rotateKeys();
  t.ok(await getUser(pool.sign()), 'token signed by the new key verifies after refresh');
  await pool.close();
});

test('verify: multiple pools accept tokens from any of them', async t => {
  const a = await startMockCognito({userPoolId: 'us-east-1_AAA'});
  const b = await startMockCognito({userPoolId: 'us-east-1_BBB'});
  const getUser = makeGetUser([{issuer: a.issuer}, {issuer: b.issuer}]);
  t.ok(await getUser(a.sign()), 'pool A token verifies');
  t.ok(await getUser(b.sign()), 'pool B token verifies');
  await a.close();
  await b.close();
});

test('verify: a token claiming one issuer but signed by another pool is rejected', async t => {
  const a = await startMockCognito({userPoolId: 'us-east-1_AAA'});
  const b = await startMockCognito({userPoolId: 'us-east-1_BBB'});
  const getUser = makeGetUser([{issuer: a.issuer}, {issuer: b.issuer}]);
  // Signed by pool B's real key, but the payload claims pool A as the issuer.
  const forged = b.sign({claims: {iss: a.issuer}});
  t.equal(await getUser(forged), null, 'per-issuer key binding rejects the cross-pool token');
  await a.close();
  await b.close();
});

test('verify: malformed input is rejected without throwing', async t => {
  const getUser = makeGetUser({region: 'us-east-1', userPoolId: 'us-east-1_X'});
  t.equal(await getUser(''), null, 'empty string');
  t.equal(await getUser('only-one-segment'), null, 'one segment');
  t.equal(await getUser('two.segments'), null, 'two segments');
  t.equal(await getUser('@@@.@@@.@@@'), null, 'undecodable segments');
});
