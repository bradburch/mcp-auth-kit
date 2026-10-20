// Every caller-influenced segment is URI-encoded so a `:` inside it (a userId like "bob:x",
// an IPv6 address) can't make two different (segment, segment) pairs share one key.
const seg = encodeURIComponent;

export const clientKey = (id: string) => `mcp:client:${seg(id)}`;
/** Keyed by the code's SHA-256 hash — a storage dump never yields redeemable codes. */
export const authCodeKey = (codeHash: string) => `mcp:auth_code:${codeHash}`;
export const accessTokenKey = (hash: string) => `mcp:token:${hash}`;
export const refreshTokenKey = (hash: string) => `mcp:refresh:${hash}`;
/** Token-family record: tracks the currently-active pair for refresh-reuse detection. */
export const tokenFamilyKey = (familyId: string) => `mcp:family:${seg(familyId)}`;
/** Keyed by the confirmation token's SHA-256 hash, like access/refresh tokens. */
export const confirmKey = (tokenHash: string) => `mcp:confirm:${tokenHash}`;
export const idempotencyKey = (userId: string, key: string) =>
  `mcp:idempotent:${seg(userId)}:${seg(key)}`;
export const userRateKey = (userId: string, hourBucket: number) =>
  `mcp:rate:${seg(userId)}:${hourBucket}`;
export const ipAuthRateKey = (ip: string, hourBucket: number) =>
  `mcp:auth_rate:${seg(ip)}:${hourBucket}`;
export const ipTokenRateKey = (ip: string, hourBucket: number) =>
  `mcp:token_rate:${seg(ip)}:${hourBucket}`;
export const cimdKey = (clientIdHash: string) => `mcp:cimd:${clientIdHash}`;
