// @ts-self-types="./index.d.ts"
import {makeGetUser} from '../index.js';
import {getGroups, getScopes} from '../claims.js';

const makeTokenSource = (header, cookie) => {
  if (!header) return req => (req.cookies && req.cookies[cookie]) || null;
  header = header.toLowerCase();
  if (!cookie) return req => req.get(header) || null;
  return req => req.get(header) || (req.cookies && req.cookies[cookie]) || null;
};

export const makeAuth = options => {
  const opt = {authHeader: 'Authorization', authCookie: 'auth', stateUserProperty: 'user', setAuthCookieOptions: null, ...options};
  const getRawUser = makeGetUser(opt.verifier, opt);
  const source = typeof opt.source == 'function' ? opt.source : makeTokenSource(opt.authHeader, opt.authCookie);
  const prop = opt.stateUserProperty;

  const setAuthCookie = (req, res, cookieOptions) => {
    const user = req[prop];
    if (user && opt.authCookie && (!req.cookies || req.cookies[opt.authCookie] !== user._token)) {
      res.cookie(opt.authCookie, user._token, {
        expires: new Date(user.exp * 1000),
        // hostname, not host: express 5 keeps the port on req.host and the cookie serializer rejects it
        domain: req.hostname,
        ...cookieOptions
      });
    }
  };

  const getUser = async (req, res, next) => {
    const token = source(req);
    // any-cast: the payload gains non-Json middleware extras (setAuthCookie).
    const user = /** @type {any} */ (await getRawUser(token));
    if (user) {
      user._token = token;
      user.setAuthCookie = setAuthCookie;
    }
    req[prop] = user;

    const oldWriteHead = res.writeHead;
    if (typeof oldWriteHead == 'function') {
      // Cookies must land before the headers flush; writeHead is the last common gate.
      res.writeHead = function (...args) {
        if (opt.setAuthCookieOptions && user) setAuthCookie(req, res, opt.setAuthCookieOptions);
        return oldWriteHead.apply(this, args);
      };
    }

    next();
  };

  const isAuthenticated = (req, res, next) => {
    if (req[prop]) return next();
    res.sendStatus(401);
  };

  const hasGroup = group => (req, res, next) => {
    const user = req[prop];
    if (!user) {
      res.sendStatus(401);
      return;
    }
    if (getGroups(user).includes(group)) return next();
    res.sendStatus(403);
  };

  const hasScope = scope => (req, res, next) => {
    const user = req[prop];
    if (!user) {
      res.sendStatus(401);
      return;
    }
    if (getScopes(user).includes(scope)) return next();
    res.sendStatus(403);
  };

  const isAllowed = validator => async (req, res, next) => {
    const user = req[prop];
    const pass = await validator(req, getGroups(user), getScopes(user));
    if (pass) return next();
    res.sendStatus(user ? 403 : 401);
  };

  return {getUser, isAuthenticated, hasGroup, hasScope, isAllowed, setAuthCookie, stateUserProperty: prop};
};

export default makeAuth;
