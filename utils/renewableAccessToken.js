'use strict';

const url = require('url');

const fetchToken = require('./fetchToken');

const gap = 5 * 60 * 1000;

let token, timeoutId;

const retrieveToken = async (uri, username, password) => {
  const urlObject = url.parse(uri);
  const options = {
    hostname: urlObject.hostname,
    path: urlObject.path,
    auth: username + ':' + password
  };
  token = await fetchToken(options);
  timeoutId && clearTimeout(timeoutId);
  timeoutId = null;
  if (token) {
    const expires = token.expires_in * 1000; // in ms
    timeoutId = setTimeout(
      () => {
        timeoutId = null;
        retrieveToken(uri, username, password);
      },
      expires > gap ? expires - gap : expires / 2
    );
  }
  return token;
};

const cancelRenewal = clearToken => {
  if (timeoutId) {
    clearTimeout(timeoutId);
    timeoutId = null;
  }
  if (clearToken) {
    token = null;
  }
};

const getToken = () => token;

module.exports.retrieveToken = retrieveToken;
module.exports.cancelRenewal = cancelRenewal;
module.exports.getToken = getToken;
