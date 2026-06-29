import type {KeyObject} from 'node:crypto';

export interface KeyStoreOptions {
  /** Custom `fetch` implementation. Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  /**
   * Minimum interval, in milliseconds, between JWKS refreshes triggered by an
   * unknown `kid`. Guards the upstream endpoint against refresh storms when a
   * stream of tokens carries unknown key ids. Defaults to `0`.
   */
  minRefreshInterval?: number;
}

export interface KeyStore {
  /** Resolves the public key for a `kid`, refreshing the JWKS on a miss. */
  get(kid: string): Promise<KeyObject | null>;
}

/** Builds a JWKS-backed key store over one or more issuer URLs. */
export function createKeyStore(issuers: string[], options?: KeyStoreOptions): KeyStore;
export default createKeyStore;
