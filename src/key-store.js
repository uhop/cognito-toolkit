import {createPublicKey} from 'node:crypto';

import {debug} from './debug.js';

const JWKS_PATH = '/.well-known/jwks.json';

export const createKeyStore = (issuers, {fetch: fetchImpl = fetch, minRefreshInterval = 0} = {}) => {
  const keys = new Map();
  let lastRefresh = -Infinity,
    inFlight = null;

  const fetchJwks = async issuer => {
    try {
      const response = await fetchImpl(issuer + JWKS_PATH);
      if (!response.ok) {
        debug('bad JWKS status %d from %s', response.status, issuer);
        return [];
      }
      const body = await response.json();
      return Array.isArray(body?.keys) ? body.keys : [];
    } catch (error) {
      debug('cannot fetch JWKS from %s: %s', issuer, error.message);
      return [];
    }
  };

  const refresh = () => {
    if (inFlight) return inFlight;
    inFlight = (async () => {
      const lists = await Promise.all(issuers.map(fetchJwks));
      for (const jwk of lists.flat()) {
        if (!jwk?.kid) continue;
        try {
          keys.set(jwk.kid, createPublicKey({key: jwk, format: 'jwk'}));
        } catch (error) {
          debug('cannot import JWK %s: %s', jwk.kid, error.message);
        }
      }
      lastRefresh = Date.now();
      inFlight = null;
    })();
    return inFlight;
  };

  return {
    get: async kid => {
      if (keys.has(kid)) return keys.get(kid);
      // Unknown kid → the pool may have rotated keys. Refresh, rate-limited.
      if (Date.now() - lastRefresh >= minRefreshInterval) await refresh();
      return keys.get(kid) ?? null;
    }
  };
};

export default createKeyStore;
