export const clientKey = (id: string) => `mcp:client:${id}`;
export const authCodeKey = (code: string) => `mcp:auth_code:${code}`;
export const accessTokenKey = (hash: string) => `mcp:token:${hash}`;
export const refreshTokenKey = (hash: string) => `mcp:refresh:${hash}`;
/** Token-family record: tracks the currently-active pair for refresh-reuse detection. */
export const tokenFamilyKey = (familyId: string) => `mcp:family:${familyId}`;
export const confirmKey = (token: string) => `mcp:confirm:${token}`;
export const idempotencyKey = (userId: string, key: string) => `mcp:idempotent:${userId}:${key}`;
export const userRateKey = (userId: string, hourBucket: number) =>
  `mcp:rate:${userId}:${hourBucket}`;
export const ipAuthRateKey = (ip: string, hourBucket: number) =>
  `mcp:auth_rate:${ip}:${hourBucket}`;
export const ipTokenRateKey = (ip: string, hourBucket: number) =>
  `mcp:token_rate:${ip}:${hourBucket}`;
export const cimdKey = (clientIdHash: string) => `mcp:cimd:${clientIdHash}`;
