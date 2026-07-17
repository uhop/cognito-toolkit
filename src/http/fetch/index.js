// @ts-self-types="./index.d.ts"
import {makeGetUser} from '../../index.js';
import {getGroups, getScopes} from '../claims.js';
import {parseCookies, serializeCookie} from '../cookies.js';

// Fetch port of the middleware family: wraps `(request: Request, ...rest) =>
// Promise<Response>` handlers, passing extra server args (Bun.serve's server,
// Deno.serve's info, Cloudflare's env/ctx) through untouched — including
// dynamodb-toolkit's createFetchAdapter handlers. Requests are immutable, so
// instead of a state property the bundle memoizes the user per Request —
// `getUser(request)` is a lookup, and guards wrap handlers.

const makeTokenSource = (header, cookie) => {
  if (!header) return request => parseCookies(request.headers.get('cookie'))[cookie] || null;
  if (!cookie) return request => request.headers.get(header) || null;
  return request => request.headers.get(header) || parseCookies(request.headers.get('cookie'))[cookie] || null;
};

const appendSetCookie = (response, cookie) => {
  try {
    response.headers.append('set-cookie', cookie);
    return response;
  } catch {
    // Immutable headers (a response obtained from fetch()) — clone into a mutable one.
    const clone = new Response(response.body, response);
    clone.headers.append('set-cookie', cookie);
    return clone;
  }
};

export const makeAuth = options => {
  const opt = {authHeader: 'Authorization', authCookie: 'auth', setAuthCookieOptions: null, ...options};
  const getRawUser = makeGetUser(opt.verifier, opt);
  const source = typeof opt.source == 'function' ? opt.source : makeTokenSource(opt.authHeader, opt.authCookie);
  const users = new WeakMap();

  const getUser = request => {
    let pending = users.get(request);
    if (!pending) {
      const token = source(request);
      pending = getRawUser(token).then(user => {
        if (user) /** @type {any} */ (user)._token = token;
        return user;
      });
      users.set(request, pending);
    }
    return pending;
  };

  const applyAuthCookie = (request, user, response, cookieOptions) => {
    if (!user || !opt.authCookie || !response) return response;
    if (parseCookies(request.headers.get('cookie'))[opt.authCookie] === user._token) return response;
    const cookie = serializeCookie(opt.authCookie, user._token, {
      expires: new Date(user.exp * 1000),
      domain: new URL(request.url).hostname,
      ...cookieOptions
    });
    return appendSetCookie(response, cookie);
  };

  const refresh = async (request, user, result) => {
    const response = await result;
    return opt.setAuthCookieOptions ? applyAuthCookie(request, user, response, opt.setAuthCookieOptions) : response;
  };

  const setAuthCookie = async (request, response, cookieOptions) => applyAuthCookie(request, await getUser(request), response, cookieOptions);

  const isAuthenticated =
    handler =>
    async (request, ...rest) => {
      const user = await getUser(request);
      if (!user) return new Response(null, {status: 401});
      return refresh(request, user, handler(request, ...rest));
    };

  const guard =
    check =>
    handler =>
    async (request, ...rest) => {
      const user = await getUser(request);
      if (!user) return new Response(null, {status: 401});
      if (!check(user)) return new Response(null, {status: 403});
      return refresh(request, user, handler(request, ...rest));
    };

  const hasGroup = group => guard(user => getGroups(user).includes(group));
  const hasScope = scope => guard(user => getScopes(user).includes(scope));

  const isAllowed =
    validator =>
    handler =>
    async (request, ...rest) => {
      const user = await getUser(request);
      const pass = await validator(request, getGroups(user), getScopes(user));
      if (pass) return refresh(request, user, handler(request, ...rest));
      return new Response(null, {status: user ? 403 : 401});
    };

  return {getUser, isAuthenticated, hasGroup, hasScope, isAllowed, setAuthCookie};
};

export default makeAuth;
