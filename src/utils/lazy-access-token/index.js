// @ts-self-types="./index.d.ts"
import {fetchToken} from '../fetch-token.js';

const GAP = 5 * 60 * 1000;

export const createLazyAccessToken = options => {
  const {url, clientId, secret, fetch} = options || {};
  let token = null,
    tokenExpires = -1;

  const getToken = () => token;

  const authorize = async () => {
    if (token && Date.now() < tokenExpires) return token;
    token = await fetchToken({url, clientId, secret, fetch});
    const expires = token.expires_in * 1000;
    tokenExpires = Date.now() + (expires > GAP ? expires - GAP : expires / 2);
    return token;
  };

  return {authorize, getToken};
};

export default createLazyAccessToken;
