'use strict';

const https = require('https');
const {promisify} = require('util');

const debug = require('debug')('cognito-toolkit');
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');

const verify = promisify(jwt.verify.bind(jwt));

let issuers = null,
  pems = null;

const preparePems = async () => {
  const jwks = await Promise.all(
    issuers.map(
      issuer =>
        new Promise(resolve => {
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
        })
    )
  );
  pems = {};
  jwks.forEach(jwk => jwk && jwk.keys.forEach(key => (pems[key.kid] = jwkToPem(key))));
};

const makeGetUser = options => {
  if (!(options instanceof Array)) {
    options = [options];
  }
  issuers = options.map(option => {
    if (!option || !option.region) {
      throw new Error('Region should be specified');
    }
    if (!option.userPoolId) {
      throw new Error('User pool ID should be specified');
    }
    return `https://cognito-idp.${option.region}.amazonaws.com/${option.userPoolId}`;
  });
  return async token => {
    !pems && (await preparePems());
    const decodedToken = jwt.decode(token, {complete: true});
    if (!decodedToken) {
      debug('Invalid token: ' + token);
      return null;
    }
    if (!issuers.some(issuer => decodedToken.payload.iss === issuer)) {
      debug('Unexpected user pool: ' + decodedToken.payload.iss);
      return null;
    }
    const pem = pems[decodedToken.header.kid];
    if (!pem) {
      debug('Unexpected kid: ' + decodedToken.header.kid);
      return null;
    }
    return verify(token, pem, {issuer: decodedToken.payload.iss}).catch(error => {
      debug('Cannot validate a token: ' + error.message);
      return null;
    });
  };
};

module.exports = makeGetUser;
