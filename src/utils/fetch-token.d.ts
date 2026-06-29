/** An OAuth2 access token as returned by the Cognito token endpoint. */
export interface AccessToken {
  access_token: string;
  token_type: string;
  expires_in: number;
  [key: string]: unknown;
}

export interface FetchTokenOptions {
  /** The Cognito domain token endpoint, e.g. `https://<domain>/oauth2/token`. */
  url: string;
  /** App client id (sent as HTTP Basic username). */
  clientId?: string;
  /** App client secret (sent as HTTP Basic password). */
  secret?: string;
  /** Custom `fetch` implementation. Defaults to the global `fetch`. */
  fetch?: typeof fetch;
}

/** POSTs a `client_credentials` grant and resolves the token (or `null`). */
export function fetchToken(options: FetchTokenOptions): Promise<AccessToken | null>;
export default fetchToken;
