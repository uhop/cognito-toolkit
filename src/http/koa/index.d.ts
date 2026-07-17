import type {Context, Middleware} from 'koa';
import type {JwtPayload} from 'aws-jwt-verify/jwt-model';
import type {TokenVerifier} from '../../index.js';

/** Options for `ctx.cookies.set()` — the common subset, typed locally to avoid a `cookies` types dependency. */
export interface CookieOptions {
  domain?: string;
  path?: string;
  expires?: Date;
  maxAge?: number;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'strict' | 'lax' | 'none' | boolean;
  overwrite?: boolean;
}

/** The decoded payload as placed on `ctx.state`, extended with the auth-cookie helpers. */
export type AuthUser<Payload extends object = JwtPayload> = Payload & {
  /** The raw token the user authenticated with. */
  _token: string;
  /** Persist the token into the auth cookie (skipped when already there). */
  setAuthCookie(ctx: Context, cookieOptions?: CookieOptions): void;
};

export interface AuthOptions<Payload extends object = JwtPayload> {
  /** An aws-jwt-verify verifier (`CognitoJwtVerifier` / `JwtVerifier`) or compatible. */
  verifier: TokenVerifier<Payload>;
  /**
   * Header carrying the raw token — used verbatim, no `Bearer` stripping (strip
   * it in a custom `source` if your clients send it). Falsy disables the header
   * source. Defaults to `'Authorization'`.
   */
  authHeader?: string | null;
  /** Cookie carrying the token. Falsy disables the cookie source and the auth-cookie refresh. Defaults to `'auth'`. */
  authCookie?: string | null;
  /** Custom token source; overrides the `authHeader` / `authCookie` lookups. */
  source?: (ctx: Context) => string | null;
  /** When set, `getUser` refreshes the auth cookie after each authenticated request using these options. */
  setAuthCookieOptions?: CookieOptions | null;
  /** The `ctx.state` property receiving the user. Defaults to `'user'`. */
  stateUserProperty?: string;
  /** Verification failures throw (aws-jwt-verify errors) instead of yielding an anonymous request. */
  throwOnError?: boolean;
}

export interface Auth<Payload extends object = JwtPayload> {
  /** Authenticates every request: `ctx.state[stateUserProperty]` becomes an `AuthUser` or `null`. */
  getUser: Middleware;
  /** 401 unless a user is present. */
  isAuthenticated: Middleware;
  /** 401 without a user; 403 without the group (`cognito:groups` claim). */
  hasGroup(group: string): Middleware;
  /** 401 without a user; 403 without the scope (space-separated `scope` claim). */
  hasScope(scope: string): Middleware;
  /** Custom rule over `(ctx, groups, scopes)`; a falsy result yields 401 (no user) or 403. */
  isAllowed(validator: (ctx: Context, groups: string[], scopes: string[]) => boolean | Promise<boolean>): Middleware;
  /** Manually persist the current user's token into the auth cookie. */
  setAuthCookie(ctx: Context, cookieOptions?: CookieOptions): void;
  /** The resolved `stateUserProperty`. */
  stateUserProperty: string;
}

/** Builds the Koa middleware family bound to one verifier and one options set. */
export function makeAuth<Payload extends object = JwtPayload>(options: AuthOptions<Payload>): Auth<Payload>;
export default makeAuth;
