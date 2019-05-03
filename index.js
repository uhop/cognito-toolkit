'use strict';

const https = require('https');
const {promisify} = require('util');

const debug = require('debug')('cognito-toolkit');
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');

const verify = promisify(jwt.verify.bind(jwt));

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
  if (!options || !options.region) {
    throw new Error('Region should be specified');
  }
  if (!options.userPoolId) {
    throw new Error('User pool ID should be specified');
  }
  issuer = `https://cognito-idp.${options.region}.amazonaws.com/${options.userPoolId}`;
  return async token => {
    !pems && await preparePems();
    const decodedToken = jwt.decode(token, {complete: true});
    if (!decodedToken) {
      debug('Invalid token: ' + token);
      return null;
    }
    if (decodedToken.payload.iss !== issuer) {
      debug('Unexpected user pool: ' + decodedToken.payload.iss);
      return null;
    }
    const pem = pems[decodedToken.header.kid];
    if (!pem) {
      debug('Unexpected kid: ' + decodedToken.header.kid);
      return null;
    }
    return verify(token, pem, {issuer}).catch(error => {
      debug('Cannot validate a token: ' + error.message);
      return null;
    });
  };
};

module.exports = getUser;
