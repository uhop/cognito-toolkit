import type {CognitoUser, JwtHeader, Algorithm} from './verify.js';

/** A single Cognito user pool to validate tokens against. */
export interface PoolOptions {
  /** AWS region, e.g. `'us-east-1'`. Required unless `issuer` is given. */
  region?: string;
  /** User pool ID, e.g. `'us-east-1_AbCdef'`. Required unless `issuer` is given. */
  userPoolId?: string;
  /**
   * Full issuer URL, overriding `region` + `userPoolId`. Useful for non-Cognito
   * OIDC providers or local testing. JWKS is fetched from
   * `${issuer}/.well-known/jwks.json`. Trailing slashes are trimmed.
   */
  issuer?: string;
}

export interface GetUserOptions {
  /**
   * Allowed signing algorithms — either an allowlist of JWA names or a
   * predicate over the token's `alg`. Defaults to `['RS256']` (what Cognito
   * uses). Only asymmetric algorithms are verifiable (see `SUPPORTED_ALGORITHMS`);
   * symmetric (`HS*`) and `none` are always rejected, so widening this list can
   * never enable an algorithm-confusion attack.
   */
  algorithms?: Algorithm[] | string[] | ((alg: string, header: JwtHeader) => boolean);
  /**
   * Optional gate run after the signature and `exp` / `nbf` checks pass.
   * Return a falsy value (or throw) to reject the token. Use it for
   * provider-specific claims such as `token_use`, `aud`, or `client_id`.
   */
  validate?: (payload: CognitoUser, header: JwtHeader) => boolean | Promise<boolean>;
  /** Custom `fetch` implementation. Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  /**
   * Minimum interval, in milliseconds, between JWKS refreshes triggered by an
   * unknown `kid` (key-rotation handling). Defaults to `0` — refresh on every
   * miss, with concurrent misses sharing a single request.
   */
  minRefreshInterval?: number;
  /** Allowed clock skew, in seconds, for `exp` / `nbf` checks. Defaults to `0`. */
  clockTolerance?: number;
}

export type {CognitoUser, JwtHeader, Algorithm};
export {SUPPORTED_ALGORITHMS} from './verify.js';

/** Validates a token and resolves to the decoded payload, or `null`. */
export type GetUser = (token: string) => Promise<CognitoUser | null>;

/**
 * Builds a token validator for one or more Cognito user pools (or any OIDC
 * issuer, via `PoolOptions.issuer`).
 *
 * The returned function takes a JWT (an id or access token) and resolves to the
 * decoded payload once the algorithm policy, signature, issuer, `kid`,
 * `exp` / `nbf`, and optional `validate` hook all pass — otherwise `null`.
 * JWKS keys are fetched lazily on first use and refreshed automatically when a
 * pool rotates its signing keys.
 */
export default function makeGetUser(options: PoolOptions | PoolOptions[], globalOptions?: GetUserOptions): GetUser;
export {makeGetUser};
