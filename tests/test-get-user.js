import test from 'tape-six';

import makeGetUser, {CognitoJwtVerifier} from 'cognito-toolkit';
import {makeKey, signWith} from './helpers/mock-cognito.js';

const userPoolId = 'us-east-1_TEST';
const issuer = `https://cognito-idp.us-east-1.amazonaws.com/${userPoolId}`;
const clientId = 'test-client';

const key = makeKey(`${userPoolId}-key-1`);
const jwks = {keys: [key.jwk]};

const makeVerifier = props => {
  const verifier = CognitoJwtVerifier.create({userPoolId, clientId, tokenUse: 'access', ...props});
  verifier.cacheJwks(jwks);
  return verifier;
};

const sign = (opts = {}) => signWith(key, {issuer, ...opts, claims: {client_id: clientId, ...opts.claims}});

test('getUser: a valid access token resolves to its payload', async t => {
  const getUser = makeGetUser(makeVerifier());
  const user = await getUser(sign());
  t.ok(user, 'user resolved');
  t.equal(user?.iss, issuer, 'issuer claim');
  t.equal(user?.token_use, 'access', 'token_use claim');
  t.equal(user?.sub, 'mock-sub', 'subject claim');
});

test('getUser: a valid id token resolves under tokenUse "id"', async t => {
  const getUser = makeGetUser(makeVerifier({tokenUse: 'id'}));
  const user = await getUser(sign({tokenUse: 'id', claims: {aud: clientId}}));
  t.ok(user, 'user resolved');
  t.equal(user?.token_use, 'id', 'token_use claim');
});

test('getUser: an absent token resolves to null', async t => {
  const getUser = makeGetUser(makeVerifier());
  t.equal(await getUser(null), null, 'null');
  t.equal(await getUser(''), null, 'empty string');
  t.equal(await getUser(undefined), null, 'undefined');
});

test('getUser: rejected tokens resolve to null', async t => {
  const getUser = makeGetUser(makeVerifier());
  t.equal(await getUser('not.a.token'), null, 'garbage');
  t.equal(await getUser(sign({expiresIn: -600})), null, 'expired');
  t.equal(await getUser(sign({claims: {client_id: 'other-client'}})), null, 'wrong client id');
  t.equal(await getUser(sign({tokenUse: 'id', claims: {aud: clientId}})), null, 'wrong token use');
});

test('getUser: throwOnError surfaces the verification error', async t => {
  const getUser = makeGetUser(makeVerifier(), {throwOnError: true});
  await t.rejects(getUser(sign({expiresIn: -600})), 'expired token throws');
  t.equal(await getUser(null), null, 'an absent token still resolves to null');
});

test('getUser: verifier argument is validated', t => {
  t.throws(() => makeGetUser(), /verifier/, 'no verifier');
  t.throws(() => makeGetUser({}), /verifier/, 'not a verifier');
});

test('getUser: works with any verify()-shaped stand-in and prime() hydrates it', async t => {
  let hydrated = 0;
  const verifier = {
    verify: async token => ({sub: 'stand-in', token}),
    hydrate: async () => void ++hydrated
  };
  const getUser = makeGetUser(verifier);
  const user = await getUser('opaque');
  t.equal(user?.sub, 'stand-in', 'stand-in payload');
  await getUser.prime();
  t.equal(hydrated, 1, 'prime() called hydrate()');
});
