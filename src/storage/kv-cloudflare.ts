import type { KvLike } from "./types.js";

export interface KVNamespaceLike {
  get(key: string): Promise<string | null>;
  put(
    key: string,
    value: string,
    opts?: { expirationTtl?: number },
  ): Promise<void>;
  delete(key: string): Promise<void>;
}

export function createCloudflareKvStorage(kv: KVNamespaceLike): KvLike {
  return {
    get: (key) => kv.get(key),
    put: (key, value, opts) =>
      kv.put(
        key,
        value,
        opts?.ttlSeconds ? { expirationTtl: opts.ttlSeconds } : undefined,
      ),
    delete: (key) => kv.delete(key),
  };
}
