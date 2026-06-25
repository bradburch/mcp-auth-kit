# Storage adapters

`mcp-server-kit` is storage-agnostic. It depends only on the three-method `KvLike` interface, which you can implement against any key-value store.

## The `KvLike` interface

```ts
interface KvLike {
  get(key: string): Promise<string | null>;
  put(
    key: string,
    value: string,
    opts?: { ttlSeconds?: number },
  ): Promise<void>;
  delete(key: string): Promise<void>;
}
```

All values are strings. Serialization (JSON, etc.) is the caller's responsibility. `ttlSeconds` is optional — if the backend doesn't support TTL natively, silently ignoring it is acceptable, though token expiry may then rely on the OAuth provider's own cleanup logic.

## Built-in adapters

> **Warning:** `createMemoryStorage()` is not persistent and is not shared across isolates or
> processes. It is suitable for local development and unit tests only. Never use it in production.

| Adapter       | Export                          | Use case                                      |
| ------------- | ------------------------------- | --------------------------------------------- |
| In-memory     | `createMemoryStorage()`         | Tests and local dev (data is lost on restart) |
| Cloudflare KV | `createCloudflareKvStorage(kv)` | Cloudflare Workers production deployments     |

`createCloudflareKvStorage` accepts any object satisfying `KVNamespaceLike` (also exported) — the subset of the Cloudflare KV API the kit uses — so it works in tests without a real KV binding.

## Example adapters

The snippets below show how to wrap common backends. They are **examples, not shipped dependencies** — `mcp-server-kit` does not install or import Redis, DynamoDB, or Postgres. Copy, adapt, and own them in your own project.

### Redis (ioredis)

```ts
import Redis from "ioredis";
import type { KvLike } from "mcp-server-kit";

export function createRedisStorage(redis: Redis): KvLike {
  return {
    async get(key) {
      return redis.get(key); // returns string | null
    },
    async put(key, value, opts) {
      if (opts?.ttlSeconds) {
        await redis.set(key, value, "EX", opts.ttlSeconds);
      } else {
        await redis.set(key, value);
      }
    },
    async delete(key) {
      await redis.del(key);
    },
  };
}
```

### DynamoDB (AWS SDK v3)

```ts
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  DeleteItemCommand,
  type AttributeValue,
} from "@aws-sdk/client-dynamodb";
import type { KvLike } from "mcp-server-kit";

export function createDynamoDbStorage(
  client: DynamoDBClient,
  tableName: string,
): KvLike {
  return {
    async get(key) {
      const res = await client.send(
        new GetItemCommand({ TableName: tableName, Key: { pk: { S: key } } }),
      );
      return res.Item?.value?.S ?? null;
    },
    async put(key, value, opts) {
      // DynamoDB TTL is a Unix epoch timestamp, not a duration.
      const Item: Record<string, AttributeValue> = {
        pk: { S: key },
        value: { S: value },
      };
      if (opts?.ttlSeconds) {
        Item.ttl = {
          N: String(Math.floor(Date.now() / 1000) + opts.ttlSeconds),
        };
      }
      await client.send(new PutItemCommand({ TableName: tableName, Item }));
    },
    async delete(key) {
      await client.send(
        new DeleteItemCommand({
          TableName: tableName,
          Key: { pk: { S: key } },
        }),
      );
    },
  };
}
```

### Postgres (node-postgres)

```ts
import type { Pool } from "pg";
import type { KvLike } from "mcp-server-kit";

// Requires a table:
//   CREATE TABLE kv_store (
//     key TEXT PRIMARY KEY,
//     value TEXT NOT NULL,
//     expires_at TIMESTAMPTZ
//   );
export function createPostgresStorage(pool: Pool): KvLike {
  return {
    async get(key) {
      const res = await pool.query<{ value: string }>(
        "SELECT value FROM kv_store WHERE key = $1 AND (expires_at IS NULL OR expires_at > NOW())",
        [key],
      );
      return res.rows[0]?.value ?? null;
    },
    async put(key, value, opts) {
      const expiresAt = opts?.ttlSeconds
        ? new Date(Date.now() + opts.ttlSeconds * 1000).toISOString()
        : null;
      await pool.query(
        `INSERT INTO kv_store (key, value, expires_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (key) DO UPDATE SET value = $2, expires_at = $3`,
        [key, value, expiresAt],
      );
    },
    async delete(key) {
      await pool.query("DELETE FROM kv_store WHERE key = $1", [key]);
    },
  };
}
```

Note: the Postgres adapter does not have automatic row expiry. Run a periodic `DELETE FROM kv_store WHERE expires_at < NOW()` job (or a Postgres cron extension) to reclaim expired rows.
