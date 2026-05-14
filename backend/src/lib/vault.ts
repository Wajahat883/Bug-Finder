/**
 * Secret Vault Adapter — abstracts secret retrieval across environments.
 *
 * Priority order:
 *   1. HashiCorp Vault (if VAULT_ADDR + VAULT_TOKEN set)
 *   2. AWS Secrets Manager (if AWS_REGION + AWS_SECRET_ARN set)
 *   3. Environment variables (dev fallback)
 *
 * Usage: const dbPassword = await vault.getSecret("MONGO_PASSWORD");
 */
import { createHash } from "crypto";
import { logger } from "./logger";

type VaultBackend = "hashicorp" | "aws" | "env";

function detectBackend(): VaultBackend {
  if (process.env["VAULT_ADDR"] && process.env["VAULT_TOKEN"]) return "hashicorp";
  if (process.env["AWS_REGION"] && process.env["AWS_SECRET_ARN"]) return "aws";
  return "env";
}

const backend = detectBackend();
const cache = new Map<string, { value: string; expires: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

async function fromHashiCorpVault(key: string): Promise<string | undefined> {
  try {
    const addr = process.env["VAULT_ADDR"]!;
    const token = process.env["VAULT_TOKEN"]!;
    const path = process.env["VAULT_SECRET_PATH"] ?? "secret/data/bugfinder";
    const res = await fetch(`${addr}/v1/${path}`, {
      headers: { "X-Vault-Token": token },
    });
    if (!res.ok) return undefined;
    const json = await res.json() as { data?: { data?: Record<string, string> } };
    return json?.data?.data?.[key];
  } catch (err) {
    logger.warn({ err }, "HashiCorp Vault fetch failed, falling back to env");
    return undefined;
  }
}

async function fromAwsSecretsManager(key: string): Promise<string | undefined> {
  try {
    // Dynamic import — AWS SDK is optional
    const { SecretsManagerClient, GetSecretValueCommand } = await import("@aws-sdk/client-secrets-manager");
    const client = new SecretsManagerClient({ region: process.env["AWS_REGION"] });
    const cmd = new GetSecretValueCommand({ SecretId: process.env["AWS_SECRET_ARN"] });
    const resp = await client.send(cmd);
    if (!resp.SecretString) return undefined;
    const parsed = JSON.parse(resp.SecretString) as Record<string, string>;
    return parsed[key];
  } catch (err) {
    logger.warn({ err }, "AWS Secrets Manager fetch failed, falling back to env");
    return undefined;
  }
}

export async function getSecret(key: string): Promise<string> {
  const now = Date.now();
  const cached = cache.get(key);
  if (cached && cached.expires > now) return cached.value;

  let value: string | undefined;

  if (backend === "hashicorp") value = await fromHashiCorpVault(key);
  else if (backend === "aws") value = await fromAwsSecretsManager(key);

  // Fall back to environment variable
  if (!value) value = process.env[key] ?? "";

  cache.set(key, { value, expires: now + CACHE_TTL_MS });
  return value;
}

/** Derive the credential vault key — prefers vault over env var */
export async function getVaultKey(): Promise<Buffer> {
  const raw = await getSecret("CREDENTIAL_VAULT_KEY");
  if (raw.length >= 32) return Buffer.from(raw.slice(0, 32), "utf8");
  return createHash("sha256").update(raw || "bug-finder-dev-vault-key-insecure").digest();
}

export const vault = { getSecret, getVaultKey, backend };
export default vault;
