// @ts-self-types="./fetch-token.d.ts"
const BODY = 'grant_type=client_credentials';

export const fetchToken = async ({url, clientId, secret, fetch: fetchImpl = fetch}) => {
  const headers = {
    'content-type': 'application/x-www-form-urlencoded',
    accept: 'application/json'
  };
  if (clientId || secret) {
    headers.authorization = 'Basic ' + Buffer.from(`${clientId}:${secret}`).toString('base64');
  }
  const response = await fetchImpl(url, {method: 'POST', headers, body: BODY});
  if (!response.ok) throw new Error('Bad status code: ' + response.status);
  try {
    // A 2xx OAuth2 token response always carries a JSON body; an empty or
    // unparseable one is a malformed response, not a "no token" result.
    return await response.json();
  } catch (error) {
    throw new Error('Invalid token response body from ' + url, {cause: error});
  }
};

export default fetchToken;
