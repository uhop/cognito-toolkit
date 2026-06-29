import {createPublicKey} from 'node:crypto';

import {debug} from './debug.js';

const JWKS_PATH = '/.well-known/jwks.json';

export const createKeyStore = (issuers, {fetch: fetchImpl = fetch, minRefreshInterval = 30_000} = {}) => {
  // Keys are scoped per issuer — never merged into a shared kid map — so a token
  // is only ever verified with a key published by the issuer it claims.
  const stores = new Map(issuers.map(issuer => [issuer, {keys: new Map(), lastRefresh: -Infinity, inFlight: null}]));

  const fetchKeys = async (issuer, store) => {
    try {
      const response = await fetchImpl(issuer + JWKS_PATH);
      if (!response.ok) {
        debug('bad JWKS status %d from %s', response.status, issuer);
        return;
      }
      const body = await response.json();
      for (const jwk of Array.isArray(body?.keys) ? body.keys : []) {
        if (!jwk?.kid) continue;
        try {
          store.keys.set(jwk.kid, createPublicKey({key: jwk, format: 'jwk'}));
        } catch (error) {
          debug('cannot import JWK %s: %s', jwk.kid, error.message);
        }
      }
    } catch (error) {
      debug('cannot fetch JWKS from %s: %s', issuer, error.message);
    }
  };

  const refresh = (issuer, store) => {
    if (store.inFlight) return store.inFlight;
    store.inFlight = (async () => {
      await fetchKeys(issuer, store);
      store.lastRefresh = Date.now();
      store.inFlight = null;
    })();
    return store.inFlight;
  };

  return {
    get: async (issuer, kid) => {
      const store = stores.get(issuer);
      if (!store) return null;
      if (store.keys.has(kid)) return store.keys.get(kid);
      // A miss can mean the issuer rotated its signing keys.
      if (Date.now() - store.lastRefresh >= minRefreshInterval) await refresh(issuer, store);
      return store.keys.get(kid) ?? null;
    },
    prime: () => Promise.all([...stores].map(([issuer, store]) => refresh(issuer, store))).then(() => undefined)
  };
};

export default createKeyStore;
