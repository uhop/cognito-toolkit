import type {JwtPayload} from 'aws-jwt-verify/jwt-model';

export {CognitoJwtVerifier, JwtVerifier} from 'aws-jwt-verify';

/**
 * Anything with an aws-jwt-verify-shaped async `verify()` — a
 * `CognitoJwtVerifier`, a generic `JwtVerifier`, or your own stand-in.
 */
export interface TokenVerifier<Payload extends object = JwtPayload> {
  /** Verifies a JWT and resolves to its payload; throws when the token is invalid. */
  verify(jwt: string): Promise<Payload>;
  /** Pre-fetches JWKS. aws-jwt-verify verifiers provide it; optional on stand-ins. */
  hydrate?(): Promise<void>;
}

export interface GetUserOptions {
  /**
   * When `true`, verification failures throw (aws-jwt-verify error classes —
   * see `aws-jwt-verify/error`) instead of resolving `null`, so callers can
   * distinguish e.g. an expired token from an invalid one. An absent token
   * still resolves `null`. Defaults to `false`.
   */
  throwOnError?: boolean;
}

/**
 * Takes a JWT (or nothing) and resolves to the decoded payload, or `null` when
 * the token is absent or fails verification.
 */
export type GetUser<Payload extends object = JwtPayload> = ((token: string | null | undefined) => Promise<Payload | null>) & {
  /** Pre-fetch the verifier's JWKS (e.g. to avoid first-request latency). */
  prime(): Promise<void>;
};

/**
 * Wraps an aws-jwt-verify verifier into the token-to-user-or-`null` shape the
 * middleware family consumes. Configure pools, audience, token use, etc. on the
 * verifier itself — see `CognitoJwtVerifier.create()`.
 */
export default function makeGetUser<Payload extends object = JwtPayload>(verifier: TokenVerifier<Payload>, options?: GetUserOptions): GetUser<Payload>;
export {makeGetUser};
