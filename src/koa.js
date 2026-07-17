import {makeGetUser} from './index.js';
import {getGroups, getScopes} from './claims.js';

const makeTokenSource = (header, cookie) => {
  if (!header) return ctx => ctx.cookies.get(cookie) || null;
  header = header.toLowerCase();
  if (!cookie) return ctx => ctx.headers[header] || null;
  return ctx => ctx.headers[header] || ctx.cookies.get(cookie) || null;
};

export const makeAuth = options => {
  const opt = {authHeader: 'Authorization', authCookie: 'auth', stateUserProperty: 'user', setAuthCookieOptions: null, ...options};
  const getRawUser = makeGetUser(opt.verifier, opt);
  const source = typeof opt.source == 'function' ? opt.source : makeTokenSource(opt.authHeader, opt.authCookie);
  const prop = opt.stateUserProperty;

  const setAuthCookie = (ctx, cookieOptions) => {
    const user = ctx.state[prop];
    if (user && opt.authCookie && ctx.cookies.get(opt.authCookie) !== user._token) {
      ctx.cookies.set(opt.authCookie, user._token, {
        expires: new Date(user.exp * 1000),
        // hostname, not host: ctx.host may carry a port, which is invalid in a cookie Domain
        domain: ctx.hostname,
        overwrite: true,
        ...cookieOptions
      });
    }
  };

  const getUser = async (ctx, next) => {
    const token = source(ctx);
    // any-cast: the payload gains non-Json middleware extras (setAuthCookie).
    const user = /** @type {any} */ (await getRawUser(token));
    if (user) {
      user._token = token;
      user.setAuthCookie = setAuthCookie;
    }
    ctx.state[prop] = user;
    await next();
    if (opt.setAuthCookieOptions && user) setAuthCookie(ctx, opt.setAuthCookieOptions);
  };

  const isAuthenticated = async (ctx, next) => {
    if (ctx.state[prop]) return next();
    ctx.status = 401;
  };

  const hasGroup = group => async (ctx, next) => {
    const user = ctx.state[prop];
    if (!user) {
      ctx.status = 401;
      return;
    }
    if (getGroups(user).includes(group)) return next();
    ctx.status = 403;
  };

  const hasScope = scope => async (ctx, next) => {
    const user = ctx.state[prop];
    if (!user) {
      ctx.status = 401;
      return;
    }
    if (getScopes(user).includes(scope)) return next();
    ctx.status = 403;
  };

  const isAllowed = validator => async (ctx, next) => {
    const user = ctx.state[prop];
    const pass = await validator(ctx, getGroups(user), getScopes(user));
    if (pass) return next();
    ctx.status = user ? 403 : 401;
  };

  return {getUser, isAuthenticated, hasGroup, hasScope, isAllowed, setAuthCookie, stateUserProperty: prop};
};

export default makeAuth;
