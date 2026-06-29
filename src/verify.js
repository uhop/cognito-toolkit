import {verify as verifySignature, constants} from 'node:crypto';

import {debug} from './debug.js';

const {RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST} = constants;

// JWA asymmetric signature algorithms → node:crypto verify parameters.
// Symmetric (HS*) and `none` are intentionally absent: signing keys come from a
// JWKS of asymmetric public keys, so there is nothing to verify a symmetric or
// unsigned token against — which is what keeps the alg-confusion / alg:none
// attacks impossible even if a caller's `algorithms` policy is misconfigured.
const ALGORITHMS = {
  RS256: {hash: 'sha256', options: {padding: RSA_PKCS1_PADDING}},
  RS384: {hash: 'sha384', options: {padding: RSA_PKCS1_PADDING}},
  RS512: {hash: 'sha512', options: {padding: RSA_PKCS1_PADDING}},
  PS256: {hash: 'sha256', options: {padding: RSA_PKCS1_PSS_PADDING, saltLength: RSA_PSS_SALTLEN_DIGEST}},
  PS384: {hash: 'sha384', options: {padding: RSA_PKCS1_PSS_PADDING, saltLength: RSA_PSS_SALTLEN_DIGEST}},
  PS512: {hash: 'sha512', options: {padding: RSA_PKCS1_PSS_PADDING, saltLength: RSA_PSS_SALTLEN_DIGEST}},
  ES256: {hash: 'sha256', options: {dsaEncoding: 'ieee-p1363'}},
  ES384: {hash: 'sha384', options: {dsaEncoding: 'ieee-p1363'}},
  ES512: {hash: 'sha512', options: {dsaEncoding: 'ieee-p1363'}}
};

export const SUPPORTED_ALGORITHMS = Object.keys(ALGORITHMS);

const decodeSegment = segment => JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));

export const verifyToken = async (token, {issuers, keyStore, isAlgorithmAllowed, validate, clockTolerance = 0}) => {
  if (typeof token !== 'string') return null;

  const parts = token.split('.');
  if (parts.length !== 3) {
    debug('malformed token: expected 3 segments, got %d', parts.length);
    return null;
  }
  const [headerB64, payloadB64, signatureB64] = parts;

  let header, payload;
  try {
    header = decodeSegment(headerB64);
    payload = decodeSegment(payloadB64);
  } catch {
    debug('cannot decode token segments');
    return null;
  }

  // Algorithm policy is enforced before anything touches the key.
  if (!isAlgorithmAllowed(header.alg, header)) {
    debug('algorithm not allowed: %s', header.alg);
    return null;
  }
  const spec = ALGORITHMS[header.alg];
  if (!spec) {
    debug('unsupported algorithm: %s', header.alg);
    return null;
  }
  if (!issuers.includes(payload.iss)) {
    debug('unexpected issuer: %s', payload.iss);
    return null;
  }

  const key = await keyStore.get(header.kid);
  if (!key) {
    debug('unknown kid: %s', header.kid);
    return null;
  }

  const signingInput = Buffer.from(headerB64 + '.' + payloadB64);
  const signature = Buffer.from(signatureB64, 'base64url');
  let ok = false;
  try {
    ok = verifySignature(spec.hash, signingInput, {key, ...spec.options}, signature);
  } catch (error) {
    // A key-type / algorithm mismatch (e.g. an ES256 header over an RSA key) throws.
    debug('signature verification error: %s', error.message);
    return null;
  }
  if (!ok) {
    debug('invalid signature');
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number' && now > payload.exp + clockTolerance) {
    debug('token expired');
    return null;
  }
  if (typeof payload.nbf === 'number' && now + clockTolerance < payload.nbf) {
    debug('token not yet valid');
    return null;
  }

  if (validate) {
    let verdict;
    try {
      verdict = await validate(payload, header);
    } catch (error) {
      debug('validate() threw: %s', error.message);
      return null;
    }
    if (!verdict) {
      debug('rejected by validate()');
      return null;
    }
  }

  return payload;
};

export default verifyToken;
