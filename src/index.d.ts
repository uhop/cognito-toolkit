import type {CognitoUser, JwtHeader, Algorithm, CognitoAuthErrorCode} from './verify.js';

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
   * Required app client id(s). When set, the token's `aud` (id tokens) or
   * `client_id` (access tokens) must match one of these — rejecting tokens
   * minted for a *different* app client in the same pool. **Strongly
   * recommended** for any pool with more than one app client.
   */
  audience?: string | string[];
  /**
   * Required `token_use` value(s) — `'access'` and/or `'id'`. When set, rejects
   * a token of the wrong type (e.g. an id token where an access token is
   * expected). Recommended.
   */
  tokenUse?: 'access' | 'id' | Array<'access' | 'id'>;
  /**
   * Optional gate run after the signature, `exp` / `nbf`, `tokenUse`, and
   * `audience` checks pass. Return a falsy value (or throw) to reject. Use it
   * for further claims such as `scope` or custom attributes.
   */
  validate?: (payload: CognitoUser, header: JwtHeader) => boolean | Promise<boolean>;
  /**
   * When `true`, the validator throws a `CognitoAuthError` (with a `.code`)
   * instead of resolving `null` on failure — so callers can distinguish e.g.
   * an expired token from an invalid one. Defaults to `false`.
   */
  throwOnError?: boolean;
  /** Custom `fetch` implementation. Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  /**
   * Minimum interval, in milliseconds, between per-issuer JWKS refreshes
   * triggered by an unknown `kid` (key-rotation handling). Defaults to `30000`.
   */
  minRefreshInterval?: number;
  /** Allowed clock skew, in seconds, for `exp` / `nbf` checks. Defaults to `0`. */
  clockTolerance?: number;
}

export type {CognitoUser, JwtHeader, Algorithm, CognitoAuthErrorCode};
export {SUPPORTED_ALGORITHMS, CognitoAuthError} from './verify.js';

/**
 * Validates a token and resolves to the decoded payload, or `null` (or throws a
 * `CognitoAuthError` when `throwOnError` is set). Carries a `prime()` to
 * pre-fetch JWKS ahead of the first request.
 */
export type GetUser = ((token: string) => Promise<CognitoUser | null>) & {
  /** Pre-fetch every configured issuer's JWKS (e.g. to avoid first-request latency). */
  prime(): Promise<void>;
};

/**
 * Builds a token validator for one or more Cognito user pools (or any OIDC
 * issuer, via `PoolOptions.issuer`).
 *
 * The returned function takes a JWT (an id or access token) and resolves to the
 * decoded payload once the algorithm policy, signature, issuer, `kid`,
 * `exp` / `nbf`, optional `tokenUse` / `audience`, and optional `validate` hook
 * all pass — otherwise `null` (or a thrown `CognitoAuthError` under
 * `throwOnError`). JWKS keys are fetched lazily per issuer and refreshed
 * automatically on key rotation.
 */
export default function makeGetUser(options: PoolOptions | PoolOptions[], globalOptions?: GetUserOptions): GetUser;
export {makeGetUser};
