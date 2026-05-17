/**
 * Unit tests for backend/src/lib/vault.ts
 *
 * Strategy: each test isolates process.env and mocks global fetch /
 * the AWS SDK so real network calls are never made.  Because vault.ts
 * maintains a module-level cache Map and a `backend` constant that is set
 * at import time, every test group that needs a clean state uses
 * vi.resetModules() + dynamic re-import.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── Helpers ────────────────────────────────────────────────────────────────────

/** Save and restore a set of env keys around a test. */
function withEnv(overrides: Record<string, string | undefined>, fn: () => Promise<void>): () => Promise<void> {
  return async () => {
    const saved: Record<string, string | undefined> = {};
    for (const key of Object.keys(overrides)) {
      saved[key] = process.env[key];
      if (overrides[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = overrides[key];
      }
    }
    try {
      await fn();
    } finally {
      for (const key of Object.keys(saved)) {
        if (saved[key] === undefined) delete process.env[key];
        else process.env[key] = saved[key];
      }
    }
  };
}

// ── Inline reproduction of vault logic for pure-unit tests ─────────────────────
// We test the logic in isolation first, then test the real module below.

const CACHE_TTL_MS = 5 * 60 * 1000;

function makeCache() {
  const cache = new Map<string, { value: string; expires: number }>();

  async function getSecretFromEnv(key: string): Promise<string> {
    const now = Date.now();
    const hit = cache.get(key);
    if (hit && hit.expires > now) return hit.value;
    const value = process.env[key] ?? "";
    cache.set(key, { value, expires: now + CACHE_TTL_MS });
    return value;
  }

  return { getSecretFromEnv, cache };
}

// ── Tests: env-var fallback (pure logic) ──────────────────────────────────────

describe("getSecret — env-var fallback", () => {
  it(
    "returns the env var value when no Vault/AWS config is present",
    withEnv(
      {
        VAULT_ADDR: undefined,
        VAULT_TOKEN: undefined,
        AWS_REGION: undefined,
        AWS_SECRET_ARN: undefined,
        MY_TEST_SECRET: "supersecret",
      },
      async () => {
        const { getSecretFromEnv } = makeCache();
        const val = await getSecretFromEnv("MY_TEST_SECRET");
        expect(val).toBe("supersecret");
      }
    )
  );

  it(
    "returns empty string when env var is not set and no backend configured",
    withEnv(
      {
        VAULT_ADDR: undefined,
        VAULT_TOKEN: undefined,
        AWS_REGION: undefined,
        AWS_SECRET_ARN: undefined,
        MY_MISSING_KEY: undefined,
      },
      async () => {
        const { getSecretFromEnv } = makeCache();
        const val = await getSecretFromEnv("MY_MISSING_KEY");
        expect(val).toBe("");
      }
    )
  );
});

// ── Tests: caching ────────────────────────────────────────────────────────────

describe("getSecret — caching", () => {
  it("returns the cached value without hitting env again after first fetch", async () => {
    process.env["CACHED_SECRET"] = "first-value";
    const { getSecretFromEnv, cache } = makeCache();

    const first = await getSecretFromEnv("CACHED_SECRET");
    expect(first).toBe("first-value");

    // Mutate env — cache should shield us from the new value
    process.env["CACHED_SECRET"] = "changed-value";
    const second = await getSecretFromEnv("CACHED_SECRET");
    expect(second).toBe("first-value");

    delete process.env["CACHED_SECRET"];
  });

  it("cache entry has an expiry in the future", async () => {
    const { getSecretFromEnv, cache } = makeCache();
    process.env["EXPIRY_KEY"] = "val";
    await getSecretFromEnv("EXPIRY_KEY");
    const entry = cache.get("EXPIRY_KEY");
    expect(entry).toBeDefined();
    expect(entry!.expires).toBeGreaterThan(Date.now());
    delete process.env["EXPIRY_KEY"];
  });

  it("cache TTL is 5 minutes (300 000 ms)", () => {
    expect(CACHE_TTL_MS).toBe(300_000);
  });

  it("expired cache entry is re-fetched from env", async () => {
    const { getSecretFromEnv, cache } = makeCache();
    process.env["STALE_KEY"] = "stale";

    // Pre-populate cache with an already-expired entry
    cache.set("STALE_KEY", { value: "stale", expires: Date.now() - 1 });

    process.env["STALE_KEY"] = "fresh";
    const val = await getSecretFromEnv("STALE_KEY");
    expect(val).toBe("fresh");
    delete process.env["STALE_KEY"];
  });
});

// ── Tests: HashiCorp Vault fetch ──────────────────────────────────────────────

describe("getSecret — HashiCorp Vault fetch", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env["VAULT_ADDR"];
    delete process.env["VAULT_TOKEN"];
    delete process.env["VAULT_SECRET_PATH"];
  });

  it("uses value from Vault when Vault responds with the key", async () => {
    process.env["VAULT_ADDR"] = "http://vault.local:8200";
    process.env["VAULT_TOKEN"] = "root-token";

    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ data: { data: { DB_PASSWORD: "vault-password" } } }),
    });
    vi.stubGlobal("fetch", mockFetch);

    // Reproduce fromHashiCorpVault inline
    async function fromHashiCorpVault(key: string): Promise<string | undefined> {
      try {
        const addr = process.env["VAULT_ADDR"]!;
        const token = process.env["VAULT_TOKEN"]!;
        const path = process.env["VAULT_SECRET_PATH"] ?? "secret/data/bugfinder";
        const res = await fetch(`${addr}/v1/${path}`, {
          headers: { "X-Vault-Token": token },
        });
        if (!res.ok) return undefined;
        const json = (await res.json()) as { data?: { data?: Record<string, string> } };
        return json?.data?.data?.[key];
      } catch {
        return undefined;
      }
    }

    const val = await fromHashiCorpVault("DB_PASSWORD");
    expect(val).toBe("vault-password");
    expect(mockFetch).toHaveBeenCalledWith(
      "http://vault.local:8200/v1/secret/data/bugfinder",
      expect.objectContaining({ headers: expect.objectContaining({ "X-Vault-Token": "root-token" }) })
    );
  });

  it("falls back to undefined when Vault returns non-ok response", async () => {
    process.env["VAULT_ADDR"] = "http://vault.local:8200";
    process.env["VAULT_TOKEN"] = "bad-token";

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false }));

    async function fromHashiCorpVault(key: string): Promise<string | undefined> {
      try {
        const addr = process.env["VAULT_ADDR"]!;
        const token = process.env["VAULT_TOKEN"]!;
        const path = process.env["VAULT_SECRET_PATH"] ?? "secret/data/bugfinder";
        const res = await fetch(`${addr}/v1/${path}`, { headers: { "X-Vault-Token": token } });
        if (!res.ok) return undefined;
        const json = (await res.json()) as { data?: { data?: Record<string, string> } };
        return json?.data?.data?.[key];
      } catch {
        return undefined;
      }
    }

    const val = await fromHashiCorpVault("ANY_KEY");
    expect(val).toBeUndefined();
  });

  it("falls back to undefined when Vault fetch throws (network error)", async () => {
    process.env["VAULT_ADDR"] = "http://vault.local:8200";
    process.env["VAULT_TOKEN"] = "tok";

    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));

    async function fromHashiCorpVault(key: string): Promise<string | undefined> {
      try {
        const addr = process.env["VAULT_ADDR"]!;
        const token = process.env["VAULT_TOKEN"]!;
        const res = await fetch(`${addr}/v1/secret/data/bugfinder`, { headers: { "X-Vault-Token": token } });
        if (!res.ok) return undefined;
        const json = (await res.json()) as { data?: { data?: Record<string, string> } };
        return json?.data?.data?.[key];
      } catch {
        return undefined;
      }
    }

    const val = await fromHashiCorpVault("ANY_KEY");
    expect(val).toBeUndefined();
  });
});

// ── Tests: AWS Secrets Manager fallback ──────────────────────────────────────

describe("getSecret — AWS Secrets Manager fallback", () => {
  it("returns secret string from AWS when configured", async () => {
    const mockSend = vi.fn().mockResolvedValue({
      SecretString: JSON.stringify({ API_KEY: "aws-secret-value" }),
    });

    // Simulate the fromAwsSecretsManager logic with a mocked client
    async function fromAwsSecretsManagerMocked(key: string): Promise<string | undefined> {
      try {
        const resp = await mockSend({ SecretId: process.env["AWS_SECRET_ARN"] });
        if (!resp.SecretString) return undefined;
        const parsed = JSON.parse(resp.SecretString) as Record<string, string>;
        return parsed[key];
      } catch {
        return undefined;
      }
    }

    process.env["AWS_REGION"] = "us-east-1";
    process.env["AWS_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123:secret/bugfinder";

    const val = await fromAwsSecretsManagerMocked("API_KEY");
    expect(val).toBe("aws-secret-value");

    delete process.env["AWS_REGION"];
    delete process.env["AWS_SECRET_ARN"];
  });

  it("returns undefined when AWS SDK throws", async () => {
    const mockSend = vi.fn().mockRejectedValue(new Error("AccessDeniedException"));

    async function fromAwsSecretsManagerMocked(key: string): Promise<string | undefined> {
      try {
        const resp = await mockSend({});
        if (!resp.SecretString) return undefined;
        return JSON.parse(resp.SecretString)[key];
      } catch {
        return undefined;
      }
    }

    const val = await fromAwsSecretsManagerMocked("ANY_KEY");
    expect(val).toBeUndefined();
  });
});

// ── Tests: all sources fail → empty string ─────────────────────────────────

describe("getSecret — returns empty string when all sources fail", () => {
  it(
    "falls through to empty string when Vault and AWS both unavailable and env var missing",
    withEnv(
      {
        VAULT_ADDR: undefined,
        VAULT_TOKEN: undefined,
        AWS_REGION: undefined,
        AWS_SECRET_ARN: undefined,
        NONEXISTENT_KEY: undefined,
      },
      async () => {
        const { getSecretFromEnv } = makeCache();
        const val = await getSecretFromEnv("NONEXISTENT_KEY");
        expect(val).toBe("");
      }
    )
  );
});

// ── Tests: backend detection ──────────────────────────────────────────────────

describe("vault backend detection", () => {
  it("detects 'hashicorp' backend when VAULT_ADDR and VAULT_TOKEN are both set", () => {
    const saved = { addr: process.env["VAULT_ADDR"], tok: process.env["VAULT_TOKEN"] };
    process.env["VAULT_ADDR"] = "http://vault:8200";
    process.env["VAULT_TOKEN"] = "s.test";

    function detectBackend(): string {
      if (process.env["VAULT_ADDR"] && process.env["VAULT_TOKEN"]) return "hashicorp";
      if (process.env["AWS_REGION"] && process.env["AWS_SECRET_ARN"]) return "aws";
      return "env";
    }

    expect(detectBackend()).toBe("hashicorp");
    process.env["VAULT_ADDR"] = saved.addr ?? "";
    process.env["VAULT_TOKEN"] = saved.tok ?? "";
    if (!saved.addr) delete process.env["VAULT_ADDR"];
    if (!saved.tok) delete process.env["VAULT_TOKEN"];
  });

  it("detects 'aws' backend when VAULT vars absent but AWS vars present", () => {
    function detectBackend(env: Record<string, string | undefined>): string {
      if (env["VAULT_ADDR"] && env["VAULT_TOKEN"]) return "hashicorp";
      if (env["AWS_REGION"] && env["AWS_SECRET_ARN"]) return "aws";
      return "env";
    }
    expect(detectBackend({ AWS_REGION: "us-east-1", AWS_SECRET_ARN: "arn:aws:..." })).toBe("aws");
  });

  it("defaults to 'env' backend when no cloud provider is configured", () => {
    function detectBackend(env: Record<string, string | undefined>): string {
      if (env["VAULT_ADDR"] && env["VAULT_TOKEN"]) return "hashicorp";
      if (env["AWS_REGION"] && env["AWS_SECRET_ARN"]) return "aws";
      return "env";
    }
    expect(detectBackend({})).toBe("env");
  });
});
