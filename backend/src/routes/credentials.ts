/**
 * Credential Vault API
 *
 * POST   /credentials              — store/update a credential set for a target
 * GET    /credentials/:targetId    — list metadata (NO plaintext returned)
 * DELETE /credentials/:id          — delete a stored credential
 * POST   /credentials/:id/test     — load and test the credential against the target
 */

import { Router, type Request } from "express";
import { z } from "zod";
import { requireAuth } from "../middlewares/rbac";
import { storeCredential, loadCredential, listCredentialMeta, deleteCredential } from "../lib/credential-vault";
import { col } from "../lib/db";
import { checkSsrf } from "../lib/ssrf-guard";
import { ObjectId } from "mongodb";

const storeCredentialSchema = z.object({
  target_id: z.string().min(1, "target_id is required"),
  type: z.enum(["bearer", "cookie", "basic", "apikey"], { errorMap: () => ({ message: "type must be bearer, cookie, basic, or apikey" }) }),
  value: z.string().min(1, "value is required").max(4096),
  username: z.string().max(256).optional(),
  label: z.string().max(100).optional(),
});

interface SessionData { userId?: string; }
type AuthReq = Request & { session: SessionData };
type AuthenticatedRequest = AuthReq;

const router = Router();

// POST /credentials — store a new credential set
router.post("/credentials", requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const parsed = storeCredentialSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.errors[0]?.message ?? "Validation failed" });
      return;
    }
    const { target_id, type, value, username, label } = parsed.data;

    // Verify target belongs to this user
    const target = await col("targets").findOne({
      _id: new ObjectId(target_id),
      ...(req.session.userId ? { user_id: req.session.userId } : {}),
    } as Record<string, unknown>);
    if (!target) {
      res.status(404).json({ error: "Target not found" });
      return;
    }

    const id = await storeCredential(
      target_id,
      { type: type as "bearer" | "cookie" | "basic" | "apikey", value, username, label },
      req.session.userId,
    );

    res.status(201).json({ id, message: "Credential stored securely (AES-256-GCM encrypted)" });
  } catch (err) {
    // MongoDB duplicate key — should not happen with atomic upsert, but guard anyway
    const code = (err as Record<string, unknown>)?.["code"];
    if (code === 11000) {
      res.status(409).json({ error: "A credential of this type already exists for this target. It has been updated instead." });
      return;
    }
    res.status(500).json({ error: "Failed to store credential" });
  }
});

// GET /credentials/:targetId — list credential metadata for a target (no plaintext)
router.get("/credentials/:targetId", requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const { targetId } = req.params as { targetId: string };

    // Verify target ownership
    const target = await col("targets").findOne({
      _id: new ObjectId(targetId),
      ...(req.session.userId ? { user_id: req.session.userId } : {}),
    } as Record<string, unknown>);
    if (!target) {
      res.status(404).json({ error: "Target not found" });
      return;
    }

    const meta = await listCredentialMeta(targetId);
    res.json({ credentials: meta });
  } catch {
    res.status(500).json({ error: "Failed to list credentials" });
  }
});

// DELETE /credentials/:id — remove a stored credential
router.delete("/credentials/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const { id } = req.params as { id: string };
    await deleteCredential(id);
    res.json({ message: "Credential deleted" });
  } catch {
    res.status(500).json({ error: "Failed to delete credential" });
  }
});

// POST /credentials/:id/test — verify the credential works against the target
router.post("/credentials/:id/test", requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const { id } = req.params as { id: string };
    const cred = await loadCredential(id);
    if (!cred) {
      res.status(404).json({ error: "Credential not found or decryption failed" });
      return;
    }

    const { target_url } = req.body as { target_url?: string };
    if (!target_url) {
      res.status(400).json({ error: "target_url is required for testing" });
      return;
    }

    const ssrfResult = checkSsrf(target_url);
    if (!ssrfResult.allowed) {
      res.status(400).json({ error: ssrfResult.reason ?? "SSRF blocked" });
      return;
    }

    const headers: Record<string, string> = {};
    if (cred.type === "bearer") headers["Authorization"] = `Bearer ${cred.value}`;
    else if (cred.type === "cookie") headers["Cookie"] = cred.value;
    else if (cred.type === "apikey") headers["X-Api-Key"] = cred.value;
    else if (cred.type === "basic") {
      const encoded = Buffer.from(`${cred.username ?? ""}:${cred.value}`).toString("base64");
      headers["Authorization"] = `Basic ${encoded}`;
    }

    const testRes = await fetch(target_url, {
      method: "GET",
      headers,
      signal: AbortSignal.timeout(8000),
      redirect: "follow",
    }).catch((err: Error) => ({ status: 0, ok: false, statusText: err.message }));

    const status = testRes.status;
    const ok = status >= 200 && status < 400;

    res.json({
      status,
      ok,
      authenticated: ok && status !== 401 && status !== 403,
      message: ok
        ? `Credential verified — server responded ${status}`
        : `Credential test failed — server responded ${status}`,
    });
  } catch {
    res.status(500).json({ error: "Credential test failed" });
  }
});

export default router;
