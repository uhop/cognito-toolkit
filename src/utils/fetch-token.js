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
  const text = await response.text();
  return text ? JSON.parse(text) : null;
};

export default fetchToken;
