import test from 'tape-six';

import {createLazyAccessToken} from 'cognito-toolkit/utils/lazy-access-token';
import {createRenewableAccessToken} from 'cognito-toolkit/utils/renewable-access-token';

import {startMockCognito} from './helpers/mock-cognito.js';

test('lazy: authorize() fetches once and caches until expiry', async t => {
  const pool = await startMockCognito();
  const lazy = createLazyAccessToken({url: pool.tokenEndpoint, clientId: 'id', secret: 'secret'});

  t.equal(lazy.getToken(), null, 'no token before authorize()');
  const token = await lazy.authorize();
  t.equal(token.access_token, 'mock-access-token', 'token fetched');
  t.equal(lazy.getToken(), token, 'getToken() returns the cached token');

  await lazy.authorize();
  t.equal(pool.tokenRequests(), 1, 'second authorize() reuses the cached token');
  await pool.close();
});

test('lazy: a custom fetch is honored', async t => {
  let calls = 0;
  const fetch = async () => (++calls, {ok: true, status: 200, json: async () => ({access_token: 'x', token_type: 'Bearer', expires_in: 3600})});
  const lazy = createLazyAccessToken({url: 'https://example/oauth2/token', clientId: 'id', secret: 's', fetch});
  const token = await lazy.authorize();
  t.equal(token.access_token, 'x');
  t.equal(calls, 1, 'custom fetch used');
});

test('tokens: an unparseable 2xx body throws (and chains the cause) rather than resolving null', async t => {
  const parseError = new SyntaxError('Unexpected end of JSON input');
  const fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => {
      throw parseError;
    }
  });
  const lazy = createLazyAccessToken({url: 'https://example/oauth2/token', clientId: 'id', secret: 's', fetch});
  try {
    await lazy.authorize();
    t.fail('should have thrown');
  } catch (error) {
    t.matchString(error.message, /Invalid token response body/, 'wraps with a clear message');
    t.equal(error.cause, parseError, 'chains the original parse error as cause');
  }
});

test('renewable: retrieveToken() fetches and exposes the token', async t => {
  const pool = await startMockCognito();
  const holder = createRenewableAccessToken({url: pool.tokenEndpoint, clientId: 'id', secret: 'secret'});

  const token = await holder.retrieveToken();
  t.equal(token.access_token, 'mock-access-token', 'token fetched');
  t.equal(holder.getToken(), token, 'getToken() returns the live token');

  holder.cancelRenewal(true);
  t.equal(holder.getToken(), null, 'cancelRenewal(true) drops the token');
  await pool.close();
});

test('renewable: a bad status code rejects', async t => {
  const fetch = async () => ({ok: false, status: 401, text: async () => ''});
  const holder = createRenewableAccessToken({url: 'https://example/oauth2/token', clientId: 'id', secret: 's', fetch});
  await t.rejects(holder.retrieveToken(), /Bad status code: 401/, 'propagates the HTTP error');
  holder.cancelRenewal();
});
