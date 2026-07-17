import type {JwtPayload} from 'aws-jwt-verify/jwt-model';

/** The `cognito:groups` claim as an array — `[]` when absent or malformed. */
export function getGroups(user: JwtPayload | null | undefined): string[];

/** The space-separated `scope` claim as an array — `[]` when absent or malformed. */
export function getScopes(user: JwtPayload | null | undefined): string[];
