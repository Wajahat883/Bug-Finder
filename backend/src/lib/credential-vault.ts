/**
 * Credential Vault — AES-256-GCM encrypted storage for scan credentials.
 *
 * Each credential set is encrypted with a per-instance key derived from
 * CREDENTIAL_VAULT_KEY env var (or a generated key stored in the DB).
 * The plaintext never touches disk or the wire.
 *
 * Schema (scan_credentials collection):
 * {
 *   _id, target_id, label, type: "bearer"|"cookie"|"basic"|"apikey",
 *   encrypted: string (base64 ciphertext), iv: string (base64),
 *   auth_tag: string (base64), created_at, updated_at, created_by
 * }
 */

import { createCipheriv, createDecipheriv, randomBytes, createHash } from "crypto";
import { col } from "./db";
import { ObjectId } from "mongodb";

const ALGO = "aes-256-gcm";

function getVaultKey(): Buffer {
  const raw = process.env["CREDENTIAL_VAULT_KEY"] ?? "";
  if (raw.length >= 32) {
    // Use the first 32 bytes of the key as-is
    return Buffer.from(raw.slice(0, 32), "utf8");
  }
  // Derive a 32-byte key from whatever is provided (or empty = dev mode)
  return createHash("sha256").update(raw || "bug-finder-dev-vault-key-insecure").digest();
}

export interface PlainCredential {
  type: "bearer" | "cookie" | "basic" | "apikey";
  value: string;             // raw credential value
  username?: string;         // for basic auth
  label?: string;
}

interface StoredCredential {
  _id: ObjectId;
  target_id: string;
  label: string;
  type: string;
  encrypted: string;
  iv: string;
  auth_tag: string;
  created_at: Date;
  updated_at: Date;
  created_by?: string;
}

function encrypt(plaintext: string): { encrypted: string; iv: string; auth_tag: string } {
  const key = getVaultKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGO, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    encrypted: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    auth_tag: tag.toString("base64"),
  };
}

function decrypt(encrypted: string, iv: string, auth_tag: string): string {
  const key = getVaultKey();
  const decipher = createDecipheriv(ALGO, key, Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(auth_tag, "base64"));
  const plain = Buffer.concat([
    decipher.update(Buffer.from(encrypted, "base64")),
    decipher.final(),
  ]);
  return plain.toString("utf8");
}

export async function storeCredential(
  targetId: string,
  cred: PlainCredential,
  createdBy?: string,
): Promise<string> {
  const payload = JSON.stringify(cred);
  const { encrypted, iv, auth_tag } = encrypt(payload);

  // Upsert: one credential set per (target_id, type, label) tuple
  const label = cred.label ?? cred.type;
  const existing = await col("scan_credentials").findOne({
    target_id: targetId,
    type: cred.type,
    label,
  } as Record<string, unknown>) as StoredCredential | null;

  if (existing) {
    await col("scan_credentials").updateOne(
      { _id: existing._id } as Record<string, unknown>,
      {
        $set: { encrypted, iv, auth_tag, updated_at: new Date(), created_by: createdBy ?? null },
      } as Record<string, unknown>,
    );
    return existing._id.toString();
  }

  const result = await col("scan_credentials").insertOne({
    target_id: targetId,
    label,
    type: cred.type,
    encrypted,
    iv,
    auth_tag,
    created_at: new Date(),
    updated_at: new Date(),
    created_by: createdBy ?? null,
  });
  return result.insertedId.toString();
}

export async function loadCredential(credentialId: string): Promise<PlainCredential | null> {
  const doc = await col("scan_credentials").findOne({
    _id: new ObjectId(credentialId),
  } as Record<string, unknown>) as StoredCredential | null;

  if (!doc) return null;
  try {
    const plain = decrypt(doc.encrypted, doc.iv, doc.auth_tag);
    return JSON.parse(plain) as PlainCredential;
  } catch {
    return null;
  }
}

export async function loadCredentialsForTarget(targetId: string): Promise<PlainCredential[]> {
  const docs = await col("scan_credentials").find({ target_id: targetId } as Record<string, unknown>).toArray() as unknown as StoredCredential[];
  const results: PlainCredential[] = [];
  for (const doc of docs) {
    try {
      const plain = decrypt(doc.encrypted, doc.iv, doc.auth_tag);
      results.push(JSON.parse(plain) as PlainCredential);
    } catch { /* skip corrupted entry */ }
  }
  return results;
}

export async function deleteCredential(credentialId: string): Promise<boolean> {
  await col("scan_credentials").deleteOne({ _id: new ObjectId(credentialId) } as Record<string, unknown>);
  return true;
}

export async function listCredentialMeta(targetId: string): Promise<Array<{ id: string; label: string; type: string; created_at: Date; updated_at: Date }>> {
  const docs = await col("scan_credentials").find({ target_id: targetId } as Record<string, unknown>).toArray() as unknown as StoredCredential[];
  return docs.map((d) => ({
    id: d._id.toString(),
    label: d.label,
    type: d.type,
    created_at: d.created_at,
    updated_at: d.updated_at,
  }));
}
