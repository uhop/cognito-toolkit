// A self-contained, zero-dependency stand-in for a Cognito user pool, used by
// the test suite. It mints real RS256-signed JWTs, serves the matching JWKS at
// `${issuer}/.well-known/jwks.json`, and answers `client_credentials` at
// `/oauth2/token` — so both the verify path and the token utilities can be
// exercised end-to-end over a real loopback HTTP server, no Docker required.

import http from 'node:http';
import {generateKeyPairSync, sign, constants} from 'node:crypto';

const {RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST} = constants;

const base64url = buf => buf.toString('base64url');
const encodeJson = value => base64url(Buffer.from(JSON.stringify(value)));

const EC_CURVE = {ES256: 'P-256', ES384: 'P-384', ES512: 'P-521'};
const SIGN = {
  RS256: {hash: 'sha256', options: {padding: RSA_PKCS1_PADDING}},
  RS384: {hash: 'sha384', options: {padding: RSA_PKCS1_PADDING}},
  RS512: {hash: 'sha512', options: {padding: RSA_PKCS1_PADDING}},
  PS256: {hash: 'sha256', options: {padding: RSA_PKCS1_PSS_PADDING, saltLength: RSA_PSS_SALTLEN_DIGEST}},
  ES256: {hash: 'sha256', options: {dsaEncoding: 'ieee-p1363'}},
  ES384: {hash: 'sha384', options: {dsaEncoding: 'ieee-p1363'}},
  ES512: {hash: 'sha512', options: {dsaEncoding: 'ieee-p1363'}}
};

export const makeKey = (kid, alg = 'RS256') => {
  const {publicKey, privateKey} = alg.startsWith('ES')
    ? generateKeyPairSync('ec', {namedCurve: EC_CURVE[alg]})
    : generateKeyPairSync('rsa', {modulusLength: 2048});
  const jwk = {...publicKey.export({format: 'jwk'}), kid, alg, use: 'sig'};
  return {kid, alg, privateKey, jwk};
};

export const signWith = (key, {issuer, claims = {}, expiresIn = 3600, alg = key.alg || 'RS256', tokenUse = 'access'}) => {
  const now = Math.floor(Date.now() / 1000);
  const header = {alg, kid: key.kid, typ: 'JWT'};
  const payload = {iss: issuer, token_use: tokenUse, sub: 'mock-sub', iat: now, exp: now + expiresIn, ...claims};
  const signingInput = encodeJson(header) + '.' + encodeJson(payload);
  const spec = SIGN[alg] || SIGN.RS256;
  return signingInput + '.' + base64url(sign(spec.hash, Buffer.from(signingInput), {key: key.privateKey, ...spec.options}));
};

export const startMockCognito = async ({region = 'us-east-1', userPoolId = 'us-east-1_TEST', alg = 'RS256', tokenResponse} = {}) => {
  // Real Cognito `kid`s are globally unique hashes; keep them unique per pool
  // so multi-pool key stores don't collide on a shared id.
  const kid = n => `${userPoolId}-key-${n}`;
  let current = makeKey(kid(1), alg);
  let served = [current];
  let tokenRequests = 0;
  let jwksRequests = 0;

  const server = http.createServer((req, res) => {
    const {pathname} = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && pathname.endsWith('/.well-known/jwks.json')) {
      ++jwksRequests;
      res.setHeader('content-type', 'application/json');
      return res.end(JSON.stringify({keys: served.map(k => k.jwk)}));
    }
    if (req.method === 'POST' && pathname.endsWith('/oauth2/token')) {
      ++tokenRequests;
      res.setHeader('content-type', 'application/json');
      return res.end(JSON.stringify(tokenResponse ?? {access_token: 'mock-access-token', token_type: 'Bearer', expires_in: 3600}));
    }
    res.statusCode = 404;
    res.end('not found');
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const {port} = server.address();
  const issuer = `http://127.0.0.1:${port}/${userPoolId}`;
  const tokenEndpoint = `http://127.0.0.1:${port}/oauth2/token`;

  return {
    issuer,
    tokenEndpoint,
    region,
    userPoolId,
    /** Sign a token with the current (served) key. */
    sign: (opts = {}) => signWith(current, {issuer, ...opts}),
    /** Sign with a freshly generated key that is NOT in the served JWKS. */
    signForeign: (opts = {}) => signWith(makeKey('foreign'), {issuer, ...opts}),
    /** Add a new signing key (kept alongside the old) and make it current. */
    rotateKeys: () => {
      current = makeKey(kid(served.length + 1), alg);
      served = [...served, current];
      return current.kid;
    },
    tokenRequests: () => tokenRequests,
    jwksRequests: () => jwksRequests,
    close: () => new Promise(resolve => server.close(resolve))
  };
};

export default startMockCognito;
