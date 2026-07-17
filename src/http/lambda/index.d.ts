import type {APIGatewayProxyEvent, APIGatewayProxyEventV2, APIGatewayProxyResult, APIGatewayProxyStructuredResultV2, ALBEvent, ALBResult} from 'aws-lambda';
import type {JwtPayload} from 'aws-jwt-verify/jwt-model';
import type {TokenVerifier} from '../../index.js';
import type {CookieOptions} from '../cookies.js';

export type {CookieOptions};

/** Any of the event shapes this port accepts: API Gateway v1, v2 / Function URL, ALB. */
export type LambdaEvent = APIGatewayProxyEvent | APIGatewayProxyEventV2 | ALBEvent;

/** Union of the result envelopes — all share the `{statusCode, body, headers?}` surface. */
export type LambdaResult = APIGatewayProxyResult | APIGatewayProxyStructuredResultV2 | ALBResult;

/** The decoded payload as resolved by `getUser`, extended with the raw token. */
export type AuthUser<Payload extends object = JwtPayload> = Payload & {
  /** The raw token the user authenticated with. */
  _token: string;
};

/** A Lambda handler: event in, result envelope out; the context arg flows through. */
export type LambdaHandler = (event: LambdaEvent, ...rest: any[]) => LambdaResult | Promise<LambdaResult>;

export interface AuthOptions<Payload extends object = JwtPayload> {
  /** An aws-jwt-verify verifier (`CognitoJwtVerifier` / `JwtVerifier` / `AlbJwtVerifier`-shaped) or compatible. */
  verifier: TokenVerifier<Payload>;
  /**
   * Header carrying the raw token — looked up case-insensitively across event
   * shapes; used verbatim, no `Bearer` stripping. Falsy disables the header
   * source. Defaults to `'Authorization'`.
   */
  authHeader?: string | null;
  /**
   * Cookie carrying the token (v2 `event.cookies` or the `Cookie` header);
   * also the cookie the auth-cookie helpers write. Falsy disables both.
   * Defaults to `'auth'`.
   */
  authCookie?: string | null;
  /** Custom token source; overrides the `authHeader` / `authCookie` lookups. */
  source?: (event: LambdaEvent) => string | null;
  /** When set, guards refresh the auth cookie on the results they pass through, using these options. */
  setAuthCookieOptions?: CookieOptions | null;
  /** Verification failures throw (aws-jwt-verify errors) instead of yielding an anonymous request. */
  throwOnError?: boolean;
}

export interface Auth<Payload extends object = JwtPayload> {
  /**
   * Resolve the event's user (or `null`). Memoized per event object — guards
   * and handlers share one verification, so calling it again is free.
   */
  getUser(event: LambdaEvent): Promise<AuthUser<Payload> | null>;
  /** Wrap a handler: 401 without a user, otherwise the handler runs. */
  isAuthenticated(handler: LambdaHandler): LambdaHandler;
  /** Wrap a handler: 401 without a user; 403 without the group (`cognito:groups` claim). */
  hasGroup(group: string): (handler: LambdaHandler) => LambdaHandler;
  /** Wrap a handler: 401 without a user; 403 without the scope (space-separated `scope` claim). */
  hasScope(scope: string): (handler: LambdaHandler) => LambdaHandler;
  /** Wrap a handler with a custom rule over `(event, groups, scopes)`; falsy → 401 (anonymous) / 403. */
  isAllowed(validator: (event: LambdaEvent, groups: string[], scopes: string[]) => boolean | Promise<boolean>): (handler: LambdaHandler) => LambdaHandler;
  /**
   * Persist the event's token into the auth cookie on a result envelope
   * (skipped when the cookie already holds it) — shape-aware: v2 `cookies`
   * array, v1 / ALB headers, `multiValueHeaders` when the trigger demands it.
   * Mutates and returns the result.
   */
  setAuthCookie(event: LambdaEvent, result: LambdaResult, cookieOptions?: CookieOptions): Promise<LambdaResult>;
}

/**
 * Builds the Lambda middleware family bound to one verifier and one options
 * set. Behind API Gateway proper, prefer the built-in Cognito / JWT authorizer
 * (verification without invoking the function); this port's niche is Function
 * URLs, ALB, and local-debug bridges.
 */
export function makeAuth<Payload extends object = JwtPayload>(options: AuthOptions<Payload>): Auth<Payload>;
export default makeAuth;
