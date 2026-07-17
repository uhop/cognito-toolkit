import type {JwtPayload} from 'aws-jwt-verify/jwt-model';
import type {TokenVerifier} from '../../index.js';
import type {CookieOptions} from '../cookies.js';

export type {CookieOptions};

/** The decoded payload as resolved by `getUser`, extended with the raw token. */
export type AuthUser<Payload extends object = JwtPayload> = Payload & {
  /** The raw token the user authenticated with. */
  _token: string;
};

/** A Fetch-style handler: `Request` in, `Response` out; extra server args flow through. */
export type FetchHandler = (request: Request, ...rest: any[]) => Response | Promise<Response>;

export interface AuthOptions<Payload extends object = JwtPayload> {
  /** An aws-jwt-verify verifier (`CognitoJwtVerifier` / `JwtVerifier`) or compatible. */
  verifier: TokenVerifier<Payload>;
  /**
   * Header carrying the raw token — used verbatim, no `Bearer` stripping (strip
   * it in a custom `source` if your clients send it). Falsy disables the header
   * source. Defaults to `'Authorization'`.
   */
  authHeader?: string | null;
  /** Cookie carrying the token; also the cookie the auth-cookie helpers write. Falsy disables both. Defaults to `'auth'`. */
  authCookie?: string | null;
  /** Custom token source; overrides the `authHeader` / `authCookie` lookups. */
  source?: (request: Request) => string | null;
  /** When set, guards refresh the auth cookie on the responses they pass through, using these options. */
  setAuthCookieOptions?: CookieOptions | null;
  /** Verification failures throw (aws-jwt-verify errors) instead of yielding an anonymous request. */
  throwOnError?: boolean;
}

export interface Auth<Payload extends object = JwtPayload> {
  /**
   * Resolve the request's user (or `null`). Memoized per `Request` — guards and
   * handlers share one verification, so calling it again is free.
   */
  getUser(request: Request): Promise<AuthUser<Payload> | null>;
  /** Wrap a handler: 401 without a user, otherwise the handler runs. */
  isAuthenticated(handler: FetchHandler): FetchHandler;
  /** Wrap a handler: 401 without a user; 403 without the group (`cognito:groups` claim). */
  hasGroup(group: string): (handler: FetchHandler) => FetchHandler;
  /** Wrap a handler: 401 without a user; 403 without the scope (space-separated `scope` claim). */
  hasScope(scope: string): (handler: FetchHandler) => FetchHandler;
  /** Wrap a handler with a custom rule over `(request, groups, scopes)`; falsy → 401 (anonymous) / 403. */
  isAllowed(validator: (request: Request, groups: string[], scopes: string[]) => boolean | Promise<boolean>): (handler: FetchHandler) => FetchHandler;
  /**
   * Persist the request's token into the auth cookie on a response (skipped when
   * the cookie already holds it). Returns the response to use — a clone when the
   * original's headers were immutable.
   */
  setAuthCookie(request: Request, response: Response, cookieOptions?: CookieOptions): Promise<Response>;
}

/** Builds the Fetch middleware family bound to one verifier and one options set. */
export function makeAuth<Payload extends object = JwtPayload>(options: AuthOptions<Payload>): Auth<Payload>;
export default makeAuth;
