// @ts-self-types="./claims.d.ts"
export const getGroups = user => (user && Array.isArray(user['cognito:groups']) ? user['cognito:groups'] : []);

export const getScopes = user => (user && typeof user.scope == 'string' ? user.scope.split(' ') : []);
