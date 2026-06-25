import type { KvLike } from "./types.js";

export function createMemoryStorage(
  now: () => number = () => Date.now(),
): KvLike {
  const store = new Map<string, { value: string; expiresAt: number | null }>();

  const live = (key: string) => {
    const entry = store.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && now() >= entry.expiresAt) {
      store.delete(key);
      return null;
    }
    return entry;
  };

  return {
    async get(key) {
      return live(key)?.value ?? null;
    },
    async put(key, value, opts) {
      const expiresAt = opts?.ttlSeconds
        ? now() + opts.ttlSeconds * 1000
        : null;
      store.set(key, { value, expiresAt });
    },
    async delete(key) {
      store.delete(key);
    },
  };
}
