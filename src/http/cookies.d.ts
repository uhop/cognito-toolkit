/** Cookie options for the hand-rolled serializer shared by the fetch and lambda ports. */
export interface CookieOptions {
  /** Set by `ctx.cookies.set` (koa) to replace an existing cookie of the same name. */
  overwrite?: boolean;
  domain?: string;
  /** Defaults to `'/'`. */
  path?: string;
  expires?: Date;
  maxAge?: number;
  secure?: boolean;
  /** Defaults to `true` — pass `false` explicitly to emit a script-readable cookie. */
  httpOnly?: boolean;
  sameSite?: 'strict' | 'lax' | 'none' | 'Strict' | 'Lax' | 'None';
}

/** Parse a `Cookie:` header into a first-value-wins name → value record. */
export function parseCookies(header: string | null | undefined): Record<string, string>;

/** Serialize one `Set-Cookie` value. */
export function serializeCookie(name: string, value: string, options: CookieOptions): string;

/**
 * Auth-cookie attribute defaults shared by all four ports: `httpOnly` and
 * `sameSite: 'lax'` always, `secure` following the request's scheme. Caller
 * options win, so any attribute can be overridden or switched off.
 */
export function authCookieDefaults(secureConnection: boolean | undefined, options: CookieOptions): CookieOptions;
