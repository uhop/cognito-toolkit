'use strict';

const https = require('https');

const debug = require('debug')('koa:cognito-middleware');
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');

const getTokenFromHeader = header => {
  header = header.toLowerCase();
  return ctx => ctx.headers[header] || null;
};

let issuer = null,
  pems = null;

const preparePems = async () => {
  const jwks = await new Promise(resolve => {
    let data = '';
    const clientRequest = https.request(issuer + '/.well-known/jwks.json', response => {
      if (response.statusCode >= 400) {
        debug('Bad status code: ' + response.statusCode);
        return resolve(null);
      }
      response.setEncoding('utf8');
      response.on('data', chunk => (data += chunk));
      response.on('end', () => resolve(data ? JSON.parse(data) : null));
    });
    clientRequest.on('error', error => {
      debug('Cannot retrieve jwks from the user pool: ' + issuer);
      resolve(null);
    });
    clientRequest.end();
  });
  pems = {};
  jwks.keys.forEach(key => (pems[key.kid] = jwkToPem(key)));
};

const getUser = options => {
  const opt = {source: 'Authorization', userPoolId: '', region: ''};
  options && Object.assign(opt, options);
  if (typeof opt.source == 'string') {
    opt.source = getTokenFromHeader(opt.source);
  }
  if (!opt.region) {
    throw new Error('Region should be specified');
  }
  if (!opt.userPoolId) {
    throw new Error('User pool ID should be specified');
  }
  issuer = `https://cognito-idp.${opt.region}.amazonaws.com/${opt.userPoolId}`;
  return async (ctx, next) => {
    ctx.state.user = null;
    const token = opt.source(ctx);
    check: if (token) {
      !pems && await preparePems();
      const decodedToken = jwt.decode(token, {complete: true});
      if (!decodedToken) {
        debug('Invalid token: ' + token);
        break check;
      }
      if (decodedToken.payload.iss !== issuer) {
        debug('Unexpected user pool: ' + decodedToken.payload.iss);
        break check;
      }
      const pem = pems[decodedToken.header.kid];
      if (!pem) {
        debug('Unexpected kid: ' + decodedToken.header.kid);
        break check;
      }
      try {
        ctx.state.user = jwt.verify(token, pem, {issuer}); // throws errors!
      } catch (error) {
        debug('Cannot validate a token: ' + error.message);
        break check;
      }
    }
    return next();
  };
};

const isAuthenticated = async (ctx, next) => {
  if (ctx.state.user) return next();
  ctx.status = 401;
};

const hasGroup = group => async (ctx, next) => {
  if (ctx.state.user) {
    const groups = ctx.state.user['cognito:groups'];
    if (groups && groups instanceof Array && groups.some(g => g === group)) return next();
    ctx.status = 403;
  }
  ctx.status = 401;
};

const hasScope = scope => async (ctx, next) => {
  if (ctx.state.user) {
    const scopes = ctx.state.user.scope;
    if (scopes && typeof scopes == 'string' && scope.split(' ').some(s => s === scope)) return next();
    ctx.status = 403;
  }
  ctx.status = 401;
};

const isAllowed = validator => async (ctx, next) => {
  const scopes = ctx.state.user && ctx.state.user.scope && ctx.state.user.scope.split(' ') || [],
    groups = ctx.state.user && ctx.state.user['cognito:groups'] || [];
  const pass = await validator(ctx, groups, scopes);
  if (pass) return next();
  ctx.status = ctx.state.user ? 403 : 401;
};

getUser.isAuthenticated = isAuthenticated;
getUser.hasGroup = hasGroup;
getUser.hasScope = hasScope;
getUser.isAllowed = isAllowed;

module.exports = getUser;
