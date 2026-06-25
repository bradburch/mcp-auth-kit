import type { RateLimitConfig } from "./config.js";
import type { KvLike } from "./storage/types.js";
import { ipAuthRateKey, ipTokenRateKey, userRateKey } from "./storage/keys.js";

const DEFAULT_USER_PER_HOUR = 50;
const DEFAULT_IP_AUTHORIZE_PER_HOUR = 10;
const DEFAULT_IP_TOKEN_PER_HOUR = 30;
const TTL_SECONDS = 3600;

export interface RateLimiter {
  checkUser(userId: string): Promise<boolean>;
  checkIpAuthorize(ip: string): Promise<boolean>;
  checkIpToken(ip: string): Promise<boolean>;
}

async function checkBucket(
  storage: KvLike,
  key: string,
  limit: number,
): Promise<boolean> {
  const raw = await storage.get(key);
  const count = raw === null ? 0 : parseInt(raw, 10);
  if (count >= limit) return false;
  await storage.put(key, String(count + 1), { ttlSeconds: TTL_SECONDS });
  return true;
}

export function createRateLimiter({
  storage,
  now = () => Date.now(),
  config = {},
}: {
  storage: KvLike;
  now?: () => number;
  config?: RateLimitConfig;
}): RateLimiter {
  const userLimit = config.userPerHour ?? DEFAULT_USER_PER_HOUR;
  const ipAuthLimit =
    config.ipAuthorizePerHour ?? DEFAULT_IP_AUTHORIZE_PER_HOUR;
  const ipTokenLimit = config.ipTokenPerHour ?? DEFAULT_IP_TOKEN_PER_HOUR;

  const hourBucket = () => Math.floor(now() / 3_600_000);

  return {
    checkUser: (userId) =>
      checkBucket(storage, userRateKey(userId, hourBucket()), userLimit),
    checkIpAuthorize: (ip) =>
      checkBucket(storage, ipAuthRateKey(ip, hourBucket()), ipAuthLimit),
    checkIpToken: (ip) =>
      checkBucket(storage, ipTokenRateKey(ip, hourBucket()), ipTokenLimit),
  };
}
