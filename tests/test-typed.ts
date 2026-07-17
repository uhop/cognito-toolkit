import test from 'tape-six';

import makeGetUser, {CognitoJwtVerifier, type GetUser, type TokenVerifier} from 'cognito-toolkit';
import {makeAuth as makeKoaAuth, type Auth as KoaAuth} from 'cognito-toolkit/koa';
import {makeAuth as makeExpressAuth, type Auth as ExpressAuth} from 'cognito-toolkit/express';
import {createLazyAccessToken, type LazyAccessToken} from 'cognito-toolkit/utils/lazy-access-token';

const verifier = CognitoJwtVerifier.create({userPoolId: 'us-east-1_X', clientId: 'client', tokenUse: 'access'});

test('typed: makeGetUser returns a GetUser', async t => {
  const getUser: GetUser = makeGetUser(verifier);
  const user = await getUser('not.a.token');
  t.equal(user, null, 'garbage rejected');
});

test('typed: a structural stand-in satisfies TokenVerifier', async t => {
  const standIn: TokenVerifier<{sub: string}> = {verify: async () => ({sub: 'x'})};
  const getUser = makeGetUser(standIn);
  const user = await getUser('opaque');
  t.equal(user?.sub, 'x', 'typed payload');
});

test('typed: middleware factories return Auth bundles', t => {
  const koa: KoaAuth = makeKoaAuth({verifier});
  t.equal(typeof koa.getUser, 'function');
  t.equal(typeof koa.hasGroup('g'), 'function');
  t.equal(koa.stateUserProperty, 'user');

  const express: ExpressAuth = makeExpressAuth({verifier, stateUserProperty: 'account'});
  t.equal(typeof express.isAuthenticated, 'function');
  t.equal(typeof express.hasScope('s'), 'function');
  t.equal(express.stateUserProperty, 'account');
});

test('typed: createLazyAccessToken returns a holder', t => {
  const holder: LazyAccessToken = createLazyAccessToken({url: 'https://example/oauth2/token', clientId: 'id', secret: 's'});
  t.equal(typeof holder.authorize, 'function');
  t.equal(holder.getToken(), null);
});
