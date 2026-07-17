/** Cookie options for the hand-rolled serializer shared by the fetch and lambda ports. */
export interface CookieOptions {
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
