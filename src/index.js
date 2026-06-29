import {createKeyStore} from './key-store.js';
import {verifyToken, SUPPORTED_ALGORITHMS, CognitoAuthError} from './verify.js';
import {debug} from './debug.js';

const issuerFromPool = pool => {
  if (!pool) throw new Error('Pool options should be specified');
  if (pool.issuer) return pool.issuer.replace(/\/+$/, '');
  if (!pool.region) throw new Error('Region should be specified');
  if (!pool.userPoolId) throw new Error('User pool ID should be specified');
  return `https://cognito-idp.${pool.region}.amazonaws.com/${pool.userPoolId}`;
};

const normalizeAlgorithms = algorithms => {
  if (typeof algorithms === 'function') return algorithms;
  const allowed = new Set(algorithms || ['RS256']);
  return alg => allowed.has(alg);
};

const toArray = value => (value == null ? undefined : Array.isArray(value) ? value : [value]);

const makeGetUser = (options, globalOptions) => {
  const pools = Array.isArray(options) ? options : [options];
  const issuers = pools.map(issuerFromPool);
  const {fetch, minRefreshInterval, clockTolerance, algorithms, validate, audience, tokenUse, throwOnError} = globalOptions || {};
  const keyStore = createKeyStore(issuers, {fetch, minRefreshInterval});
  const verifyOptions = {
    issuers,
    keyStore,
    isAlgorithmAllowed: normalizeAlgorithms(algorithms),
    validate,
    clockTolerance,
    audience: toArray(audience),
    tokenUse: toArray(tokenUse)
  };
  const getUser = async token => {
    try {
      return await verifyToken(token, verifyOptions);
    } catch (error) {
      if (throwOnError) throw error;
      // Only the expected verification failures degrade to `null`; real bugs propagate.
      if (error instanceof CognitoAuthError) {
        debug('token rejected (%s): %s', error.code, error.message);
        return null;
      }
      throw error;
    }
  };
  getUser.prime = () => keyStore.prime();
  return getUser;
};

export default makeGetUser;
export {makeGetUser, SUPPORTED_ALGORITHMS, CognitoAuthError};
