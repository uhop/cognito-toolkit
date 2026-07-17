import type {AccessToken} from '../fetch-token.js';

export interface AccessTokenOptions {
  /** The Cognito domain token endpoint, e.g. `https://<domain>/oauth2/token`. */
  url: string;
  /** App client id (sent as HTTP Basic username). */
  clientId?: string;
  /** App client secret (sent as HTTP Basic password). */
  secret?: string;
  /** Custom `fetch` implementation. Defaults to the global `fetch`. */
  fetch?: typeof fetch;
}

export interface LazyAccessToken {
  /** Returns a cached unexpired token, or fetches a fresh one on demand. Throws on a failed fetch. */
  authorize(): Promise<AccessToken>;
  /** Returns the current token without fetching (may be `null`). */
  getToken(): AccessToken | null;
}

/**
 * Creates a lazy client-credentials token holder. Each call to `authorize()`
 * reuses the cached token until it nears expiry, then fetches a fresh one.
 * State is per-instance — call this once per credential set.
 */
export function createLazyAccessToken(options: AccessTokenOptions): LazyAccessToken;
export default createLazyAccessToken;
export type {AccessToken};
