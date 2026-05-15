import { Router } from "express";
import { ObjectId } from "mongodb";
import crypto from "crypto";
import { z } from "zod";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const VALID_EVENTS = ["scan.completed", "finding.created", "finding.critical", "finding.high", "remediation.created"] as const;
const createWebhookSchema = z.object({
  url: z.string().url("Must be a valid URL"),
  events: z.array(z.enum(VALID_EVENTS)).min(1, "At least one event is required"),
  secret: z.string().max(256).optional(),
  name: z.string().max(100).optional(),
  project_id: z.string().optional(),
});
const patchWebhookSchema = z.object({ enabled: z.boolean() });

// AES-256-GCM key derived from env var, padded/truncated to exactly 32 bytes
const WEBHOOK_KEY = Buffer.from(
  (process.env["WEBHOOK_SECRET_KEY"] ?? "bugfinder-webhook-key-32chars!!")
    .slice(0, 32)
    .padEnd(32, "0")
);

function encryptSecret(plain: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", WEBHOOK_KEY, iv);
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return iv.toString("hex") + ":" + enc.toString("hex") + ":" + tag.toString("hex");
}

function decryptSecret(encrypted: string): string {
  try {
    const parts = encrypted.split(":");
    if (parts.length !== 3) return encrypted; // legacy plaintext fallback
    const [ivHex, encHex, tagHex] = parts;
    const iv = Buffer.from(ivHex!, "hex");
    const enc = Buffer.from(encHex!, "hex");
    const tag = Buffer.from(tagHex!, "hex");
    const decipher = crypto.createDecipheriv("aes-256-gcm", WEBHOOK_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
  } catch {
    return encrypted; // fallback for legacy plaintext secrets
  }
}

function signWebhookPayload(secret: string, body: string): string {
  return "sha256=" + crypto.createHmac("sha256", secret).update(body).digest("hex");
}

/**
 * Core delivery function — sends one webhook, logs the delivery, updates
 * consecutive_failures / auto-disable, and schedules a retry on failure.
 * `hook._retry_attempt` (0-based) controls whether more retries are queued.
 */
async function deliverWebhook(
  hook: Record<string, unknown>,
  body: string,
  eventName: string
): Promise<void> {
  const encSecret = hook["secret"] ? String(hook["secret"]) : null;
  const secret = encSecret ? decryptSecret(encSecret) : null;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Webhook-ID": String(hook["_id"]),
    "X-Webhook-Event": eventName,
  };
  if (secret) headers["X-Hub-Signature-256"] = signWebhookPayload(secret, body);

  const start = Date.now();
  let responseStatus = 0;
  let responseBody = "";
  let ok = false;

  try {
    const r = await fetch(String(hook["url"]), {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(15000),
    });
    responseStatus = r.status;
    ok = r.ok;
    responseBody = (await r.text()).slice(0, 500);
  } catch (err) {
    responseBody = String((err as Error).message).slice(0, 500);
  }

  const latency = Date.now() - start;

  // Log every delivery attempt
  await col("webhook_deliveries").insertOne({
    webhook_id: String(hook["_id"]),
    event: eventName,
    request_body: body.slice(0, 2000),
    response_status: responseStatus,
    response_body: responseBody,
    ok,
    latency_ms: latency,
    created_at: new Date(),
  });

  if (ok) {
    // Reset failure counter on success
    await col("webhooks").updateOne(
      { _id: hook["_id"] } as Record<string, unknown>,
      {
        $set: {
          last_triggered: new Date(),
          last_status: responseStatus,
          last_ok: true,
          consecutive_failures: 0,
        },
        $inc: { delivery_count: 1 },
      } as Record<string, unknown>
    );
  } else {
    // Increment failure counter; auto-disable at 10
    const current = (await col("webhooks").findOne(
      { _id: hook["_id"] } as Record<string, unknown>
    )) as Record<string, unknown> | null;

    const failures = ((current?.["consecutive_failures"] as number) ?? 0) + 1;
    const updateFields: Record<string, unknown> = {
      last_triggered: new Date(),
      last_status: responseStatus,
      last_ok: false,
    };

    if (failures >= 10) {
      updateFields["enabled"] = false;
      updateFields["auto_disabled"] = true;
      updateFields["auto_disabled_at"] = new Date();
      logger.warn(
        { webhookId: String(hook["_id"]) },
        "Webhook auto-disabled after 10 consecutive failures"
      );
    }

    await col("webhooks").updateOne(
      { _id: hook["_id"] } as Record<string, unknown>,
      {
        $set: updateFields,
        $inc: { consecutive_failures: 1 },
      } as Record<string, unknown>
    );

    // Schedule retry if we haven't exhausted 3 attempts (delays: 1m / 5m / 30m)
    const attempt = (hook["_retry_attempt"] as number) ?? 0;
    if (attempt < 3) {
      const delays = [60_000, 300_000, 1_800_000];
      const delay = delays[attempt] ?? 1_800_000;
      await col("webhook_retries").insertOne({
        webhook_id: String(hook["_id"]),
        event: eventName,
        payload: body,
        attempt: attempt + 1,
        scheduled_at: new Date(Date.now() + delay),
        created_at: new Date(),
      });
    }
  }
}

/**
 * Public export consumed by other parts of the app.
 * Fires all matching, enabled webhooks for the given event.
 * Filters by project_id when the webhook has one set.
 */
export async function triggerWebhooks(
  event: string,
  payload: Record<string, unknown>
): Promise<void> {
  try {
    const hooks = (await col("webhooks")
      .find({ events: event, enabled: true } as Record<string, unknown>)
      .toArray()) as Array<Record<string, unknown>>;

    for (const hook of hooks) {
      // Per-project filtering: skip if hook is scoped to a different project
      if (
        hook["project_id"] &&
        payload["project_id"] &&
        hook["project_id"] !== payload["project_id"]
      ) {
        continue;
      }

      const body = JSON.stringify({
        event,
        timestamp: new Date().toISOString(),
        ...payload,
      });

      // Fire-and-forget — errors are logged inside deliverWebhook
      deliverWebhook(hook, body, event).catch((err) =>
        logger.warn({ err }, "Webhook delivery error")
      );
    }
  } catch (err) {
    logger.error({ err }, "triggerWebhooks error");
  }
}

// ---------------------------------------------------------------------------
// Background retry runner — polls every 60 s for due retry jobs
// ---------------------------------------------------------------------------
function startRetryRunner(): void {
  setInterval(async () => {
    try {
      const due = (await col("webhook_retries")
        .find({ scheduled_at: { $lte: new Date() } } as Record<string, unknown>)
        .limit(20)
        .toArray()) as Array<Record<string, unknown>>;

      for (const retry of due) {
        // Delete first to avoid duplicate processing
        await col("webhook_retries").deleteOne(
          { _id: retry["_id"] } as Record<string, unknown>
        );

        const hook = (await col("webhooks").findOne({
          _id: new ObjectId(String(retry["webhook_id"])),
        } as Record<string, unknown>)) as Record<string, unknown> | null;

        if (!hook || !hook["enabled"]) continue;

        await deliverWebhook(
          { ...hook, _retry_attempt: retry["attempt"] },
          String(retry["payload"]),
          String(retry["event"])
        );
      }
    } catch (err) {
      logger.warn({ err }, "Webhook retry runner error");
    }
  }, 60_000);
}

startRetryRunner();

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
const router = Router();

// List all webhooks (mask secret)
router.get("/webhooks", requireAuth, async (_req, res) => {
  try {
    const hooks = (await col("webhooks")
      .find({})
      .sort({ created_at: -1 })
      .toArray()) as Array<Record<string, unknown>>;
    res.json(
      hooks.map((h) => ({ ...h, id: String(h["_id"]), secret: h["secret"] ? "***" : null }))
    );
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create webhook
router.post("/webhooks", requireAuth, async (req, res) => {
  try {
    const parsed = createWebhookSchema.safeParse(req.body);
    if (!parsed.success)
      return res
        .status(400)
        .json({ error: parsed.error.errors[0]?.message ?? "Validation failed" });

    const { url, events, secret, name, project_id } = parsed.data;
    const encryptedSecret = secret ? encryptSecret(secret) : null;

    const insert = await col("webhooks").insertOne({
      url,
      events,
      secret: encryptedSecret,
      name: name ?? url,
      project_id: project_id ?? null,
      enabled: true,
      created_at: new Date(),
      delivery_count: 0,
      consecutive_failures: 0,
      last_triggered: null,
    });

    const saved = (await col("webhooks").findOne({
      _id: insert.insertedId,
    })) as Record<string, unknown>;

    res
      .status(201)
      .json({ ...saved, id: String(saved["_id"]), secret: secret ? "***" : null });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Enable / disable webhook
router.patch("/webhooks/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const parsed = patchWebhookSchema.safeParse(req.body);
    if (!parsed.success)
      return res
        .status(400)
        .json({ error: parsed.error.errors[0]?.message ?? "Validation failed" });

    const { enabled } = parsed.data;
    const updateFields: Record<string, unknown> = { enabled };
    if (enabled) updateFields["auto_disabled"] = false; // re-enable clears auto-disable flag

    await col("webhooks").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $set: updateFields }
    );
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete webhook
router.delete("/webhooks/:id", requireAuth, async (req, res) => {
  try {
    await col("webhooks").deleteOne(
      { _id: new ObjectId(req.params.id) } as Record<string, unknown>
    );
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Test webhook (sends a synthetic test event)
router.post("/webhooks/:id/test", requireAuth, async (req, res) => {
  try {
    const hook = (await col("webhooks").findOne({
      _id: new ObjectId(req.params.id),
    } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!hook) return res.status(404).json({ error: "Not found" });

    const body = JSON.stringify({
      event: "test",
      timestamp: new Date().toISOString(),
      message: "Bug Finder Pro webhook test",
    });

    await deliverWebhook(hook, body, "test");
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

// List delivery log for a webhook (last 50)
router.get("/webhooks/:id/deliveries", requireAuth, async (req, res) => {
  try {
    const deliveries = await col("webhook_deliveries")
      .find({ webhook_id: req.params.id } as Record<string, unknown>)
      .sort({ created_at: -1 })
      .limit(50)
      .toArray();
    res.json(deliveries.map((d) => ({ ...d, id: String(d["_id"]) })));
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Replay a specific delivery
router.post(
  "/webhooks/:id/deliveries/:deliveryId/replay",
  requireAuth,
  async (req, res) => {
    try {
      const delivery = (await col("webhook_deliveries").findOne({
        _id: new ObjectId(req.params.deliveryId),
      } as Record<string, unknown>)) as Record<string, unknown> | null;
      if (!delivery) return res.status(404).json({ error: "Delivery not found" });

      const hook = (await col("webhooks").findOne({
        _id: new ObjectId(req.params.id),
      } as Record<string, unknown>)) as Record<string, unknown> | null;
      if (!hook) return res.status(404).json({ error: "Webhook not found" });

      await deliverWebhook(
        hook,
        String(delivery["request_body"] ?? "{}"),
        String(delivery["event"] ?? "replay")
      );

      res.json({ ok: true, message: "Replay queued" });
    } catch {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// List pending retries
router.get("/webhooks/retries", requireAuth, async (_req, res) => {
  try {
    const retries = await col("webhook_retries")
      .find({})
      .sort({ scheduled_at: 1 })
      .limit(100)
      .toArray();
    res.json(retries.map((r) => ({ ...r, id: String(r["_id"]) })));
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
