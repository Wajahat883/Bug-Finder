import { pool } from "./pgDb";
import { logger } from "./logger";

export async function ensureAppSchema(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id          TEXT PRIMARY KEY,
      username    TEXT UNIQUE NOT NULL,
      email       TEXT UNIQUE NOT NULL,
      password    TEXT NOT NULL,
      role        TEXT NOT NULL DEFAULT 'analyst',
      first_name  TEXT,
      last_name   TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      updated_at  TIMESTAMPTZ DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name TEXT;

    CREATE TABLE IF NOT EXISTS sessions (
      sid         TEXT PRIMARY KEY,
      sess        JSONB NOT NULL,
      expire      TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_expire_idx ON sessions(expire);

    CREATE TABLE IF NOT EXISTS audit_log (
      id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      user_id     TEXT,
      username    TEXT,
      action      TEXT NOT NULL,
      resource    TEXT,
      resource_id TEXT,
      details     JSONB,
      ip          TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS audit_log_created_idx ON audit_log(created_at DESC);

    CREATE TABLE IF NOT EXISTS webhooks (
      id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      name        TEXT NOT NULL,
      url         TEXT NOT NULL,
      events      TEXT[] NOT NULL DEFAULT '{}',
      active      BOOLEAN DEFAULT TRUE,
      secret      TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  logger.info("App schema ready");
}
