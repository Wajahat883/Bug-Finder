import Redis from "ioredis";
import { logger } from "./logger";

let _client: Redis | null = null;

export function getRedis(): Redis {
  if (_client) return _client;
  const url = process.env["REDIS_URL"] ?? "redis://localhost:6379";
  _client = new Redis(url, { lazyConnect: true, enableOfflineQueue: false, maxRetriesPerRequest: 1 });
  _client.on("error", (err) => logger.warn({ err }, "Redis error"));
  return _client;
}

export async function redisGet(key: string): Promise<string | null> {
  try { return await getRedis().get(key); } catch { return null; }
}

export async function redisSet(key: string, value: string, ttlSeconds: number): Promise<void> {
  try { await getRedis().set(key, value, "EX", ttlSeconds); } catch { /* non-fatal */ }
}

export async function redisDel(key: string): Promise<void> {
  try { await getRedis().del(key); } catch { /* non-fatal */ }
}
