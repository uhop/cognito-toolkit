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

export interface RenewableAccessTokenOptions extends AccessTokenOptions {
  /**
   * Delay, in milliseconds, before retrying a **scheduled** renewal that
   * failed — the cycle keeps retrying until a fetch succeeds or
   * `cancelRenewal()` is called. Defaults to `60000` (one minute).
   */
  retryInterval?: number;
  /**
   * Called with the error each time a scheduled renewal fails (direct
   * `retrieveToken()` calls throw instead). Without it, failures are only
   * visible on the `NODE_DEBUG=cognito-toolkit` channel.
   */
  onError?: (error: unknown) => void;
}

export interface RenewableAccessToken {
  /**
   * Fetches a token and schedules an automatic refresh shortly before it
   * expires. Returns the freshly fetched token (throws on a failed fetch). The
   * refresh timer is `unref`ed, so it never keeps the process alive on its own.
   */
  retrieveToken(): Promise<AccessToken>;
  /** Cancels the scheduled refresh (or pending retry); pass `true` to also drop the cached token. */
  cancelRenewal(clearToken?: boolean): void;
  /** Returns the current token without fetching (may be `null`). */
  getToken(): AccessToken | null;
}

/**
 * Creates a self-renewing client-credentials token holder. State is
 * per-instance — call this once per credential set. Always read the live token
 * via `getToken()`; the renewal swaps it out over time. A failed scheduled
 * renewal keeps the previous token and retries every `retryInterval` ms.
 */
export function createRenewableAccessToken(options: RenewableAccessTokenOptions): RenewableAccessToken;
export default createRenewableAccessToken;
export type {AccessToken};
