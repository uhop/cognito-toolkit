'use strict';

const url = require('url');

const fetchToken = require('./fetchToken');

const gap = 5 * 60 * 1000;

let options, token, tokenExpires = -1;

const setCredentials = (uri, username, password) => {
  const urlObject = url.parse(uri);
  options = {
    hostname: urlObject.hostname,
    path: urlObject.path,
    port: urlObject.port || 443,
    auth: username + ':' + password
  };
  token = null;
  tokenExpires = -1;
};

const getToken = () => token;

const authorize = async () => {
  if (token && Date.now() < tokenExpires) return token;
  if (options) {
    token = await fetchToken(options);
    tokenExpires = -1;
    if (token) {
      const expires = token.expires_in * 1000; // in ms
      tokenExpires = Date.now() + (expires > gap ? expires - gap : expires / 2)
    }
    return token;
  }
  return null;
};

module.exports.setCredentials = setCredentials;
module.exports.getToken = getToken;
module.exports.authorize = authorize;
