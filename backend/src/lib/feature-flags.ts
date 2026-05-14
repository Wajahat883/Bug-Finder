/**
 * Feature Flags — runtime toggle per role / user / global.
 * Stored in MongoDB `feature_flags` collection.
 * Admin can toggle via API. Frontend uses useFeatureFlag() hook.
 */
import { col } from "./db";
import { logger } from "./logger";

export interface FeatureFlag {
  name: string;
  enabled: boolean;
  description?: string;
  allowed_roles?: string[];    // if set, only these roles see the flag as enabled
  allowed_user_ids?: string[]; // per-user override
  rollout_percent?: number;    // 0-100 gradual rollout
  created_at: Date;
  updated_at: Date;
}

const cache = new Map<string, { flag: FeatureFlag; expires: number }>();
const TTL = 30_000; // 30s cache

export async function getFlag(name: string): Promise<FeatureFlag | null> {
  const now = Date.now();
  const hit = cache.get(name);
  if (hit && hit.expires > now) return hit.flag;
  try {
    const flag = await col("feature_flags").findOne({ name }) as FeatureFlag | null;
    if (flag) cache.set(name, { flag, expires: now + TTL });
    return flag;
  } catch (err) {
    logger.warn({ err }, "Feature flag lookup failed");
    return null;
  }
}

export async function isFlagEnabled(
  name: string,
  context?: { userId?: string; role?: string }
): Promise<boolean> {
  const flag = await getFlag(name);
  if (!flag) return false;
  if (!flag.enabled) return false;

  if (context?.role && flag.allowed_roles?.length) {
    if (!flag.allowed_roles.includes(context.role)) return false;
  }
  if (context?.userId && flag.allowed_user_ids?.length) {
    if (flag.allowed_user_ids.includes(context.userId)) return true;
  }
  if (flag.rollout_percent !== undefined && flag.rollout_percent < 100) {
    // Deterministic rollout based on userId hash
    if (!context?.userId) return false;
    const hash = context.userId.split("").reduce((acc, c) => acc + c.charCodeAt(0), 0);
    return (hash % 100) < flag.rollout_percent;
  }

  return true;
}

export async function setFlag(name: string, updates: Partial<FeatureFlag>): Promise<void> {
  await col("feature_flags").updateOne(
    { name },
    {
      $set: { ...updates, updated_at: new Date() },
      $setOnInsert: { name, created_at: new Date() },
    },
    { upsert: true }
  );
  cache.delete(name); // invalidate cache
}

export async function listFlags(): Promise<FeatureFlag[]> {
  return col("feature_flags").find({}).sort({ name: 1 }).toArray() as unknown as Promise<FeatureFlag[]>;
}

// ── Default flags (seeded on startup) ────────────────────────────────────────
export const DEFAULT_FLAGS: Array<Pick<FeatureFlag, "name" | "enabled" | "description">> = [
  { name: "ai_triage",           enabled: true,  description: "AI-assisted triage scoring" },
  { name: "excel_export",        enabled: true,  description: "Export findings as Excel/CSV" },
  { name: "webauthn",            enabled: false, description: "Passkey / WebAuthn login (beta)" },
  { name: "saml_sso",            enabled: false, description: "SAML 2.0 SSO provider" },
  { name: "multi_tenant",        enabled: false, description: "Multi-tenant data isolation" },
  { name: "compliance_tags",     enabled: true,  description: "PCI-DSS/HIPAA/SOC2 compliance mapping" },
  { name: "pii_redaction",       enabled: true,  description: "Auto-redact PII in finding evidence" },
  { name: "anomaly_detection",   enabled: true,  description: "Audit log anomaly detection alerts" },
  { name: "dark_launch_scanner", enabled: false, description: "New scanner engine (10% rollout)" },
];

export async function seedDefaultFlags(): Promise<void> {
  for (const f of DEFAULT_FLAGS) {
    const exists = await col("feature_flags").findOne({ name: f.name });
    if (!exists) {
      await col("feature_flags").insertOne({
        ...f,
        allowed_roles: undefined,
        allowed_user_ids: undefined,
        rollout_percent: undefined,
        created_at: new Date(),
        updated_at: new Date(),
      });
    }
  }
}
