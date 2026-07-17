// @ts-self-types="./index.d.ts"
import {makeGetUser} from '../../index.js';
import {getGroups, getScopes} from '../claims.js';
import {parseCookies, serializeCookie} from '../cookies.js';

// AWS Lambda port of the middleware family: wraps `(event, context) => result`
// handlers across API Gateway v1, v2 / Function URL, and ALB event shapes —
// including dynamodb-toolkit's createLambdaHandler. Guards return Lambda
// result envelopes (401/403); the user is memoized per event via `getUser`.
// Note: behind API Gateway proper, the built-in Cognito / JWT authorizer is
// usually the better tool (verification without invoking the function) — this
// port's niche is Function URLs, ALB, and local-debug bridges.

// ALB sends `event.requestContext.elb`; API Gateway v2 / Function URL send
// `event.version === '2.0'`; everything else is API Gateway v1.
const detectKind = event => {
  if (event && event.requestContext && event.requestContext.elb) return 'alb';
  if (event && event.version === '2.0') return 'v2';
  return 'v1';
};

// v2 lowercases header names; v1 / ALB preserve the sender's casing; ALB
// multi-value mode null-stamps `headers` and delivers `multiValueHeaders`.
const readHeader = (event, name) => {
  const lower = name.toLowerCase();
  const headers = event.headers;
  if (headers) {
    if (lower in headers) return headers[lower];
    for (const key of Object.keys(headers)) {
      if (key.toLowerCase() === lower) return headers[key];
    }
    return null;
  }
  const multi = event.multiValueHeaders;
  if (multi) {
    for (const key of Object.keys(multi)) {
      if (key.toLowerCase() === lower) return (multi[key] && multi[key][0]) || null;
    }
  }
  return null;
};

// API Gateway v2 / Function URL carry cookies in `event.cookies: string[]`;
// v1 / ALB carry the Cookie header.
const readCookies = event => {
  if (event.cookies && event.cookies.length) return parseCookies(event.cookies.join('; '));
  return parseCookies(readHeader(event, 'cookie'));
};

// Mirror the request's header mode on the response — ALB multi-value mode
// strictly requires `multiValueHeaders` back (same rule as dynamodb-toolkit's
// lambda adapter: the null-stamped `headers` is the sentinel).
const wantsMultiValueHeaders = event => !!(event.multiValueHeaders && event.headers === null);

const deny = (event, statusCode) => {
  const result = {statusCode, body: ''};
  if (wantsMultiValueHeaders(event)) result.multiValueHeaders = {};
  return result;
};

// Attach a Set-Cookie to a handler's result envelope, shape-aware: v2 uses
// the `cookies` array; v1 / ALB use headers, lifted to multiValueHeaders when
// the trigger demands it (or when the result already carries them).
const addSetCookie = (event, kind, result, cookie) => {
  if (!result || typeof result !== 'object') return result;
  if (kind === 'v2') {
    result.cookies = [...(result.cookies || []), cookie];
    return result;
  }
  if (wantsMultiValueHeaders(event) || result.multiValueHeaders) {
    const multi = result.multiValueHeaders || (result.multiValueHeaders = {});
    multi['Set-Cookie'] = [...(multi['Set-Cookie'] || []), cookie];
    return result;
  }
  const headers = result.headers || (result.headers = {});
  headers['Set-Cookie'] = cookie;
  return result;
};

const readHostname = event => {
  const domain = event.requestContext && event.requestContext.domainName;
  const host = domain || readHeader(event, 'host');
  return host ? String(host).split(':')[0] : undefined;
};

export const makeAuth = options => {
  const opt = {authHeader: 'Authorization', authCookie: 'auth', setAuthCookieOptions: null, ...options};
  const getRawUser = makeGetUser(opt.verifier, opt);
  const defaultSource = event => readHeader(event, opt.authHeader) || (opt.authCookie && readCookies(event)[opt.authCookie]) || null;
  const source = typeof opt.source == 'function' ? opt.source : opt.authHeader ? defaultSource : event => readCookies(event)[opt.authCookie] || null;
  const users = new WeakMap();

  const getUser = event => {
    let pending = users.get(event);
    if (!pending) {
      const token = source(event);
      pending = getRawUser(token).then(user => {
        if (user) /** @type {any} */ (user)._token = token;
        return user;
      });
      users.set(event, pending);
    }
    return pending;
  };

  const applyAuthCookie = (event, user, result, cookieOptions) => {
    if (!user || !opt.authCookie || !result) return result;
    if (readCookies(event)[opt.authCookie] === user._token) return result;
    const cookie = serializeCookie(opt.authCookie, user._token, {
      expires: new Date(user.exp * 1000),
      domain: readHostname(event),
      ...cookieOptions
    });
    return addSetCookie(event, detectKind(event), result, cookie);
  };

  const refresh = async (event, user, pending) => {
    const result = await pending;
    return opt.setAuthCookieOptions ? applyAuthCookie(event, user, result, opt.setAuthCookieOptions) : result;
  };

  const setAuthCookie = async (event, result, cookieOptions) => applyAuthCookie(event, await getUser(event), result, cookieOptions);

  const isAuthenticated =
    handler =>
    async (event, ...rest) => {
      const user = await getUser(event);
      if (!user) return deny(event, 401);
      return refresh(event, user, handler(event, ...rest));
    };

  const guard =
    check =>
    handler =>
    async (event, ...rest) => {
      const user = await getUser(event);
      if (!user) return deny(event, 401);
      if (!check(user)) return deny(event, 403);
      return refresh(event, user, handler(event, ...rest));
    };

  const hasGroup = group => guard(user => getGroups(user).includes(group));
  const hasScope = scope => guard(user => getScopes(user).includes(scope));

  const isAllowed =
    validator =>
    handler =>
    async (event, ...rest) => {
      const user = await getUser(event);
      const pass = await validator(event, getGroups(user), getScopes(user));
      if (pass) return refresh(event, user, handler(event, ...rest));
      return deny(event, user ? 403 : 401);
    };

  return {getUser, isAuthenticated, hasGroup, hasScope, isAllowed, setAuthCookie};
};

export default makeAuth;
