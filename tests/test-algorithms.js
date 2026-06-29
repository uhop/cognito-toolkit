import test from 'tape-six';

import makeGetUser, {SUPPORTED_ALGORITHMS} from 'cognito-toolkit';

import {startMockCognito} from './helpers/mock-cognito.js';

const base64url = value => Buffer.from(JSON.stringify(value)).toString('base64url');

test('algorithms: SUPPORTED_ALGORITHMS lists the asymmetric family', t => {
  t.ok(SUPPORTED_ALGORITHMS.includes('RS256'), 'RS256');
  t.ok(SUPPORTED_ALGORITHMS.includes('ES256'), 'ES256');
  t.ok(SUPPORTED_ALGORITHMS.includes('PS256'), 'PS256');
  t.notOk(SUPPORTED_ALGORITHMS.includes('HS256'), 'no symmetric');
  t.notOk(SUPPORTED_ALGORITHMS.includes('none'), 'no none');
});

test('algorithms: default policy rejects a non-RS256 token even if validly signed', async t => {
  const pool = await startMockCognito({alg: 'ES256'});
  const getUser = makeGetUser({issuer: pool.issuer}); // default algorithms: ['RS256']
  t.equal(await getUser(pool.sign()), null, 'ES256 token rejected under default RS256 policy');
  await pool.close();
});

test('algorithms: an explicit allowlist accepts ES256 (future-proof / other providers)', async t => {
  const pool = await startMockCognito({alg: 'ES256'});
  const getUser = makeGetUser({issuer: pool.issuer}, {algorithms: ['ES256']});
  const user = await getUser(pool.sign({claims: {sub: 'ec-user'}}));
  t.ok(user, 'ES256 token verified');
  t.equal(user.sub, 'ec-user');
  await pool.close();
});

test('algorithms: a predicate function works as the policy', async t => {
  const pool = await startMockCognito(); // RS256
  const getUser = makeGetUser({issuer: pool.issuer}, {algorithms: alg => alg === 'RS256'});
  t.ok(await getUser(pool.sign()), 'predicate allows RS256');

  const ec = await startMockCognito({alg: 'ES256'});
  const strict = makeGetUser({issuer: ec.issuer}, {algorithms: alg => alg === 'RS256'});
  t.equal(await strict(ec.sign()), null, 'predicate rejects ES256');
  await pool.close();
  await ec.close();
});

test('algorithms: a misconfigured HS256 allowlist still cannot enable confusion', async t => {
  const pool = await startMockCognito();
  // Even if the caller foolishly allows HS256, there is no symmetric verifier —
  // a crafted HS256 token is rejected as unsupported.
  const getUser = makeGetUser({issuer: pool.issuer}, {algorithms: ['HS256', 'RS256']});
  const header = base64url({alg: 'HS256', kid: `${pool.userPoolId}-key-1`, typ: 'JWT'});
  const payload = base64url({iss: pool.issuer, sub: 'attacker', exp: Math.floor(Date.now() / 1000) + 3600});
  const forged = `${header}.${payload}.${Buffer.from('whatever').toString('base64url')}`;
  t.equal(await getUser(forged), null, 'HS256 token rejected (unsupported), no confusion');
  t.ok(await getUser(pool.sign()), 'RS256 still works from the same allowlist');
  await pool.close();
});

test('validate: a falsy verdict rejects an otherwise-valid token', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser({issuer: pool.issuer}, {validate: payload => payload.token_use === 'access'});
  t.ok(await getUser(pool.sign({tokenUse: 'access'})), 'access token accepted');
  t.equal(await getUser(pool.sign({tokenUse: 'id'})), null, 'id token rejected by validate()');
  await pool.close();
});

test('validate: a thrown error rejects rather than escaping', async t => {
  const pool = await startMockCognito();
  const getUser = makeGetUser(
    {issuer: pool.issuer},
    {
      validate: () => {
        throw new Error('boom');
      }
    }
  );
  t.equal(await getUser(pool.sign()), null, 'a throwing validate() rejects the token');
  await pool.close();
});
