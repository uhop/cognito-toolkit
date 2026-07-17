import {debug} from './debug.js';

export {CognitoJwtVerifier, JwtVerifier} from 'aws-jwt-verify';

const makeGetUser = (verifier, options) => {
  if (!verifier || typeof verifier.verify != 'function') {
    throw new TypeError('A verifier instance (e.g. CognitoJwtVerifier.create(...)) should be specified');
  }
  const {throwOnError} = options || {};
  const getUser = async token => {
    if (!token) return null;
    try {
      return await verifier.verify(token);
    } catch (error) {
      if (throwOnError) throw error;
      // Only verification failures degrade to `null`; an absent token never throws.
      debug('token rejected: %s', error && error.message);
      return null;
    }
  };
  getUser.prime = async () => {
    verifier.hydrate && (await verifier.hydrate());
  };
  return getUser;
};

export default makeGetUser;
export {makeGetUser};
