import type {KeyStore} from './key-store.js';

/** A decoded JWT header. `alg` is always present; `kid` selects the JWKS key. */
export interface JwtHeader {
  alg: string;
  kid?: string;
  typ?: string;
  [claim: string]: unknown;
}

/** A decoded, verified JWT payload. Cognito claims vary by token type. */
export type CognitoUser = Record<string, unknown>;

/** The JWA asymmetric algorithms this library can verify. */
export type Algorithm = 'RS256' | 'RS384' | 'RS512' | 'PS256' | 'PS384' | 'PS512' | 'ES256' | 'ES384' | 'ES512';

/** Every algorithm name `verifyToken` knows how to verify. */
export const SUPPORTED_ALGORITHMS: Algorithm[];

/** Why a token was rejected. The `code` on a thrown `CognitoAuthError`. */
export type CognitoAuthErrorCode =
  | 'malformed_token'
  | 'algorithm_not_allowed'
  | 'unknown_issuer'
  | 'unknown_key'
  | 'invalid_signature'
  | 'token_expired'
  | 'token_not_yet_valid'
  | 'wrong_token_use'
  | 'wrong_audience'
  | 'rejected_by_validate';

/** Thrown on a verification failure (surfaced only when `throwOnError` is set). */
export class CognitoAuthError extends Error {
  readonly name: 'CognitoAuthError';
  readonly code: CognitoAuthErrorCode;
  constructor(message: string, code: CognitoAuthErrorCode);
}

export interface VerifyOptions {
  /** Allowed issuer URLs; `payload.iss` must be one of them. */
  issuers: string[];
  /** Per-issuer key store used to resolve the signing key by `kid`. */
  keyStore: KeyStore;
  /** Predicate gating the token's `alg` before any key lookup. */
  isAlgorithmAllowed: (alg: string, header: JwtHeader) => boolean;
  /** Optional post-verification gate over the decoded payload / header. */
  validate?: (payload: CognitoUser, header: JwtHeader) => boolean | Promise<boolean>;
  /** Allowed clock skew, in seconds, for `exp` / `nbf`. Defaults to `0`. */
  clockTolerance?: number;
  /** Allowed `aud` (id tokens) / `client_id` (access tokens) values. */
  audience?: string[];
  /** Allowed `token_use` values (`'access'` / `'id'`). */
  tokenUse?: string[];
}

/**
 * Verifies a JWT: the `alg` is gated by `isAlgorithmAllowed` (never read from
 * the header to *select* the algorithm), then the signature (against the
 * claimed issuer's JWKS key for its `kid`), `iss`, `exp` / `nbf`, optional
 * `tokenUse` / `audience`, and an optional `validate` hook. Resolves to the
 * decoded payload, or throws a `CognitoAuthError`.
 */
export function verifyToken(token: string, options: VerifyOptions): Promise<CognitoUser>;
export default verifyToken;
