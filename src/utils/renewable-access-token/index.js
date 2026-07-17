// @ts-self-types="./index.d.ts"
import {debug} from '../../debug.js';
import {fetchToken} from '../fetch-token.js';

const GAP = 5 * 60 * 1000;

export const createRenewableAccessToken = options => {
  const {url, clientId, secret, fetch, retryInterval = 60 * 1000, onError} = options || {};
  let token = null,
    timeoutId = null,
    epoch = 0;

  const getToken = () => token;

  const schedule = (fn, delay) => {
    timeoutId && clearTimeout(timeoutId);
    timeoutId = setTimeout(fn, delay);
    // Don't keep the event loop alive just for the refresh timer.
    timeoutId.unref?.();
  };

  const renew = async () => {
    const started = epoch;
    try {
      await retrieveToken();
    } catch (error) {
      if (started !== epoch) return; // cancelled while in flight — stay cancelled
      debug('token renewal failed: %s', error && error.message);
      // Reschedule before the user callback: a throwing onError must not kill the cycle.
      schedule(renew, retryInterval);
      onError && onError(error);
    }
  };

  const retrieveToken = async () => {
    const started = epoch;
    const fresh = await fetchToken({url, clientId, secret, fetch});
    if (started !== epoch) return fresh; // cancelled while in flight — don't store or resurrect
    token = fresh;
    const expires = fresh.expires_in * 1000;
    schedule(renew, expires > GAP ? expires - GAP : expires / 2);
    return fresh;
  };

  const cancelRenewal = clearToken => {
    ++epoch;
    if (timeoutId) {
      clearTimeout(timeoutId);
      timeoutId = null;
    }
    if (clearToken) token = null;
  };

  return {retrieveToken, cancelRenewal, getToken};
};

export default createRenewableAccessToken;
