'use strict';

const https = require('https');
const querystring = require('querystring');

const postData = querystring.stringify({grant_type: 'client_credentials'}),
  postLength = Buffer.byteLength(postData);

const fetchToken = options => {
  // prepare the options
  const opt = {...options};
  opt.protocol = 'https:';
  opt.headers = options.headers ? {...options.headers} : {};
  if (!opt.method) opt.method = 'POST';
  const headerMap = Object.keys(opt.headers).reduce((acc, key) => (acc[key.toLowerCase()] = key, acc), {});
  opt.headers[headerMap['content-type'] || 'content-type'] = 'application/x-www-form-urlencoded';
  opt.headers[headerMap['content-length'] || 'content-length'] = postLength;
  if (!headerMap.accept) opt.headers.accept = 'application/json';
  // do the call
  return new Promise((resolve, reject) => {
    let data = '';
    const clientRequest = https.request(opt, response => {
      if (response.statusCode >= 400) {
        return reject(new Error('Bad status code: ' + response.statusCode));
      }
      response.setEncoding('utf8');
      response.on('data', chunk => (data += chunk));
      response.on('end', () => resolve(data ? JSON.parse(data) : null));
    });
    clientRequest.on('error', error => reject(error));
    clientRequest.write(postData);
    clientRequest.end();
  });
};

module.exports = fetchToken;
