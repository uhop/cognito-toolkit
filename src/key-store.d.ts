import type {KeyObject} from 'node:crypto';

export interface KeyStoreOptions {
  /** Custom `fetch` implementation. Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  /**
   * Minimum interval, in milliseconds, between JWKS refreshes triggered by an
   * unknown `kid` (per issuer). Guards the upstream endpoint against refresh
   * storms when a stream of tokens carries unknown key ids. Defaults to `30000`.
   */
  minRefreshInterval?: number;
}

export interface KeyStore {
  /** Resolves the public key for an issuer's `kid`, refreshing its JWKS on a miss. */
  get(issuer: string, kid: string): Promise<KeyObject | null>;
  /** Pre-fetch every configured issuer's JWKS. */
  prime(): Promise<void>;
}

/** Builds a per-issuer JWKS-backed key store over one or more issuer URLs. */
export function createKeyStore(issuers: string[], options?: KeyStoreOptions): KeyStore;
export default createKeyStore;
