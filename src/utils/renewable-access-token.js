import {fetchToken} from './fetch-token.js';

const GAP = 5 * 60 * 1000;

export const createRenewableAccessToken = options => {
  const {url, clientId, secret, fetch} = options || {};
  let token = null,
    timeoutId = null;

  const getToken = () => token;

  const retrieveToken = async () => {
    token = await fetchToken({url, clientId, secret, fetch});
    timeoutId && clearTimeout(timeoutId);
    timeoutId = null;
    if (token) {
      const expires = token.expires_in * 1000; // ms
      timeoutId = setTimeout(retrieveToken, expires > GAP ? expires - GAP : expires / 2);
      // Don't keep the event loop alive just for the refresh timer.
      timeoutId.unref?.();
    }
    return token;
  };

  const cancelRenewal = clearToken => {
    if (timeoutId) {
      clearTimeout(timeoutId);
      timeoutId = null;
    }
    if (clearToken) token = null;
  };

  return {retrieveToken, cancelRenewal, getToken};
};

export default createRenewableAccessToken;
