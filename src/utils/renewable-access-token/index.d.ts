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

export interface RenewableAccessToken {
  /**
   * Fetches a token and schedules an automatic refresh shortly before it
   * expires. Returns the freshly fetched token (throws on a failed fetch). The
   * refresh timer is `unref`ed, so it never keeps the process alive on its own.
   */
  retrieveToken(): Promise<AccessToken>;
  /** Cancels the scheduled refresh; pass `true` to also drop the cached token. */
  cancelRenewal(clearToken?: boolean): void;
  /** Returns the current token without fetching (may be `null`). */
  getToken(): AccessToken | null;
}

/**
 * Creates a self-renewing client-credentials token holder. State is
 * per-instance — call this once per credential set. Always read the live token
 * via `getToken()`; the renewal swaps it out over time.
 */
export function createRenewableAccessToken(options: AccessTokenOptions): RenewableAccessToken;
export default createRenewableAccessToken;
export type {AccessToken};
