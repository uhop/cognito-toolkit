import {verify as verifySignature, constants} from 'node:crypto';

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

export class CognitoAuthError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'CognitoAuthError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new CognitoAuthError(message, code);
};

const decodeSegment = segment => JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));

const toArray = value => (value == null ? [] : Array.isArray(value) ? value : [value]);

export const verifyToken = async (token, {issuers, keyStore, isAlgorithmAllowed, validate, clockTolerance = 0, audience, tokenUse}) => {
  if (typeof token !== 'string') fail('malformed_token', 'Token is not a string');

  const parts = token.split('.');
  if (parts.length !== 3) fail('malformed_token', `Expected 3 token segments, got ${parts.length}`);
  const [headerB64, payloadB64, signatureB64] = parts;

  let header, payload;
  try {
    header = decodeSegment(headerB64);
    payload = decodeSegment(payloadB64);
  } catch {
    fail('malformed_token', 'Cannot decode token segments');
  }

  if (!isAlgorithmAllowed(header.alg, header)) fail('algorithm_not_allowed', `Algorithm not allowed: ${header.alg}`);
  const spec = ALGORITHMS[header.alg];
  if (!spec) fail('algorithm_not_allowed', `Unsupported algorithm: ${header.alg}`);

  if (!issuers.includes(payload.iss)) fail('unknown_issuer', `Unexpected issuer: ${payload.iss}`);

  // Key is fetched from the JWKS of the *claimed* issuer, binding iss ↔ signing key.
  const key = await keyStore.get(payload.iss, header.kid);
  if (!key) fail('unknown_key', `No key for kid: ${header.kid}`);

  const signingInput = Buffer.from(headerB64 + '.' + payloadB64);
  const signature = Buffer.from(signatureB64, 'base64url');
  let ok = false;
  try {
    ok = verifySignature(spec.hash, signingInput, {key, ...spec.options}, signature);
  } catch (error) {
    // A key-type / algorithm mismatch (e.g. an ES256 header over an RSA key) throws.
    fail('invalid_signature', 'Signature verification error: ' + error.message);
  }
  if (!ok) fail('invalid_signature', 'Invalid signature');

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number' && now > payload.exp + clockTolerance) fail('token_expired', 'Token expired');
  if (typeof payload.nbf === 'number' && now + clockTolerance < payload.nbf) fail('token_not_yet_valid', 'Token not yet valid');

  if (tokenUse && tokenUse.length && !tokenUse.includes(payload.token_use)) {
    fail('wrong_token_use', `Unexpected token_use: ${payload.token_use}`);
  }
  if (audience && audience.length) {
    // id tokens carry the app client id in `aud`; access tokens in `client_id`.
    const claimed = new Set([...toArray(payload.aud), ...toArray(payload.client_id)]);
    if (!audience.some(a => claimed.has(a))) fail('wrong_audience', 'Token audience / client_id is not allowed');
  }

  if (validate) {
    let verdict;
    try {
      verdict = await validate(payload, header);
    } catch (error) {
      fail('rejected_by_validate', 'validate() threw: ' + error.message);
    }
    if (!verdict) fail('rejected_by_validate', 'Rejected by validate()');
  }

  return payload;
};

export default verifyToken;
