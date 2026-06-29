import {createKeyStore} from './key-store.js';
import {verifyToken, SUPPORTED_ALGORITHMS} from './verify.js';

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

const makeGetUser = (options, globalOptions) => {
  const pools = Array.isArray(options) ? options : [options];
  const issuers = pools.map(issuerFromPool);
  const {fetch, minRefreshInterval, clockTolerance, algorithms, validate} = globalOptions || {};
  const isAlgorithmAllowed = normalizeAlgorithms(algorithms);
  const keyStore = createKeyStore(issuers, {fetch, minRefreshInterval});
  return token => verifyToken(token, {issuers, keyStore, isAlgorithmAllowed, validate, clockTolerance});
};

export default makeGetUser;
export {makeGetUser, SUPPORTED_ALGORITHMS};
