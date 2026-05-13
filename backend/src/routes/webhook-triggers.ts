import { Router } from "express";
import crypto from "crypto";
import { logger } from "../lib/logger";
import { col } from "../lib/db";
import { enqueueScan } from "../services/queue/manager";

const router = Router();

function verifySignature(payload: string, signature: string, secret: string): boolean {
  const hmac = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(signature.replace("sha256=", "")));
}

// POST /webhooks/github — GitHub push webhook
router.post("/webhooks/github", async (req, res) => {
  const signature = req.headers["x-hub-signature-256"] as string | undefined;
  const secret = process.env["GITHUB_WEBHOOK_SECRET"];

  if (secret && signature) {
    const raw = JSON.stringify(req.body);
    if (!verifySignature(raw, signature, secret)) {
      return res.status(401).json({ error: "Invalid signature" });
    }
  }

  try {
    const event = req.headers["x-github-event"] as string;
    const body = req.body as Record<string, unknown>;

    if (event === "push" || event === "pull_request") {
      const repo = body.repository as Record<string, unknown> | undefined;
      const repoUrl = repo?.["html_url"] as string | undefined;
      const repoName = repo?.["full_name"] as string | undefined;

      if (repoUrl) {
        const jobId = crypto.randomUUID();

        await col("scan_jobs").insertOne({
          _id: { toHexString: () => jobId } as any,
          target_url: repoUrl,
          scan_profile: "standard",
          status: "queued",
          progress: 0,
          created_at: new Date(),
          triggered_by: "webhook-github",
          webhook_event: event,
          repo_name: repoName ?? null,
        });

        await enqueueScan({
          jobId,
          targetUrl: repoUrl,
          profile: "standard",
          validationEnabled: true,
          fuzzingEnabled: false,
          bugBountyMode: false,
        });

        logger.info({ repo: repoName, event }, "Auto-scan triggered via GitHub webhook");
        return res.json({ ok: true, jobId, message: "Scan queued" });
      }
    }

    res.json({ ok: true, message: `Event ${event} received — no scan triggered` });
  } catch (err) {
    logger.error({ err }, "GitHub webhook error");
    res.status(500).json({ error: "Webhook processing failed" });
  }
});

// POST /webhooks/gitlab — GitLab push webhook
router.post("/webhooks/gitlab", async (req, res) => {
  const token = req.headers["x-gitlab-token"] as string | undefined;
  const secret = process.env["GITLAB_WEBHOOK_SECRET"];

  if (secret && token !== secret) {
    return res.status(401).json({ error: "Invalid token" });
  }

  try {
    const body = req.body as Record<string, unknown>;
    const project = body.project as Record<string, unknown> | undefined;
    const repoUrl = project?.["web_url"] as string | undefined;

    if (repoUrl) {
      const jobId = crypto.randomUUID();

      await col("scan_jobs").insertOne({
        _id: { toHexString: () => jobId } as any,
        target_url: repoUrl,
        scan_profile: "standard",
        status: "queued",
        progress: 0,
        created_at: new Date(),
        triggered_by: "webhook-gitlab",
        repo_name: project?.["path_with_namespace"] as string ?? null,
      });

      await enqueueScan({
        jobId,
        targetUrl: repoUrl,
        profile: "standard",
        validationEnabled: true,
        fuzzingEnabled: false,
        bugBountyMode: false,
      });

      logger.info({ repo: project?.["path_with_namespace"] }, "Auto-scan triggered via GitLab webhook");
      return res.json({ ok: true, jobId, message: "Scan queued" });
    }

    res.json({ ok: true, message: "Webhook received — no scan triggered" });
  } catch (err) {
    logger.error({ err }, "GitLab webhook error");
    res.status(500).json({ error: "Webhook processing failed" });
  }
});

// POST /webhooks/trigger-scan — Manual API-based scan trigger (for CI/CD scripts)
router.post("/webhooks/trigger-scan", async (req, res) => {
  const apiKey = req.headers["x-api-key"] as string | undefined;
  const configuredKey = process.env["WEBHOOK_API_KEY"];

  if (configuredKey && apiKey !== configuredKey) {
    return res.status(401).json({ error: "Invalid API key" });
  }

  try {
    const { targetUrl, profile = "standard" } = req.body as { targetUrl?: string; profile?: string };

    if (!targetUrl) {
      return res.status(400).json({ error: "targetUrl is required" });
    }

    const jobId = crypto.randomUUID();

    await enqueueScan({
      jobId,
      targetUrl,
      profile: profile as "quick" | "standard" | "deep",
      validationEnabled: true,
      fuzzingEnabled: profile === "deep",
      bugBountyMode: profile === "deep",
    });

    logger.info({ targetUrl, profile }, "CI/CD scan triggered via API");
    return res.json({ ok: true, jobId, message: "Scan queued", targetUrl, profile });
  } catch (err) {
    logger.error({ err }, "Trigger scan error");
    res.status(500).json({ error: "Failed to trigger scan" });
  }
});

export default router;
