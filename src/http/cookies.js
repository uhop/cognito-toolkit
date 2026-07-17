// @ts-self-types="./cookies.d.ts"

export const parseCookies = header => {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) {
      const key = part.slice(0, i).trim();
      if (!(key in out)) out[key] = part.slice(i + 1).trim();
    }
  }
  return out;
};

const SAME_SITE = {strict: 'Strict', lax: 'Lax', none: 'None'};

export const serializeCookie = (name, value, options) => {
  let cookie = `${name}=${value}; Path=${options.path || '/'}`;
  if (options.expires) cookie += `; Expires=${options.expires.toUTCString()}`;
  if (options.maxAge != null) cookie += `; Max-Age=${options.maxAge}`;
  if (options.domain) cookie += `; Domain=${options.domain}`;
  if (options.secure) cookie += '; Secure';
  if (options.httpOnly !== false) cookie += '; HttpOnly';
  if (options.sameSite) cookie += `; SameSite=${SAME_SITE[String(options.sameSite).toLowerCase()] || options.sameSite}`;
  return cookie;
};
