import { EventEmitter } from "events";
import { logger } from "../../lib/logger";
import { col } from "../../lib/db";
import { runScanPipeline, scanEvents } from "../scanner/index";

interface ScanJob {
  jobId: string;
  targetUrl: string;
  profile: "quick" | "standard" | "deep";
  validationEnabled: boolean;
  fuzzingEnabled: boolean;
  bugBountyMode: boolean;
}

interface AiJob {
  type: string;
  findingId?: string;
  scanId?: string;
  payload?: Record<string, unknown>;
}

const scanQueue: ScanJob[] = [];
const aiQueue: AiJob[] = [];
let isProcessing = false;
let isAiProcessing = false;
export const queueEvents = new EventEmitter();

const MAX_CONCURRENT_SCANS = 2;
const MAX_CONCURRENT_AI = 3;
const MAX_SCAN_RETRIES = 3;
let activeScans = 0;
let activeAiJobs = 0;

interface ScanJob {
  jobId: string;
  targetUrl: string;
  profile: "quick" | "standard" | "deep";
  validationEnabled: boolean;
  fuzzingEnabled: boolean;
  bugBountyMode: boolean;
  retryCount?: number;
}

export async function enqueueScan(job: ScanJob): Promise<void> {
  scanQueue.push(job);
  logger.info({ jobId: job.jobId, target: job.targetUrl }, "Scan enqueued");
  queueEvents.emit("scan:enqueued", { jobId: job.jobId, queueSize: scanQueue.length });
  processScanQueue();
}

export async function enqueueAiJob(job: AiJob): Promise<void> {
  aiQueue.push(job);
  queueEvents.emit("ai:enqueued", { type: job.type, queueSize: aiQueue.length });
  processAiQueue();
}

async function processScanQueue(): Promise<void> {
  if (isProcessing) return;
  isProcessing = true;

  while (scanQueue.length > 0 && activeScans < MAX_CONCURRENT_SCANS) {
    const job = scanQueue.shift();
    if (!job) break;
    activeScans++;

    queueEvents.emit("scan:started", { jobId: job.jobId, activeScans });
    logger.info({ jobId: job.jobId }, "Processing scan from queue");

    try {
      await col("scan_jobs").updateOne(
        { _id: job.jobId } as never,
        { $set: { status: "running", started_at: new Date(), progress: 0 } }
      );

      await runScanPipeline({
        jobId: job.jobId,
        targetUrl: job.targetUrl,
        profile: job.profile,
        validationEnabled: job.validationEnabled,
        fuzzingEnabled: job.fuzzingEnabled,
        bugBountyMode: job.bugBountyMode,
      });

      logger.info({ jobId: job.jobId }, "Scan completed from queue");
      queueEvents.emit("scan:completed", { jobId: job.jobId, activeScans: activeScans - 1 });
    } catch (err) {
      logger.error({ err, jobId: job.jobId }, "Scan failed in queue");
      const retries = (job.retryCount ?? 0) + 1;
      if (retries <= MAX_SCAN_RETRIES) {
        job.retryCount = retries;
        scanQueue.push(job);
        logger.warn({ jobId: job.jobId, retries, maxRetries: MAX_SCAN_RETRIES }, "Re-queued failed scan for retry");
      } else {
        await col("scan_jobs").updateOne(
          { _id: job.jobId } as never,
          { $set: { status: "failed", error_message: err instanceof Error ? err.message : `Worker failure after ${MAX_SCAN_RETRIES} retries` } }
        );
        queueEvents.emit("scan:failed", { jobId: job.jobId, error: err instanceof Error ? err.message : "Max retries exceeded" });
        logger.error({ jobId: job.jobId }, "Scan permanently failed after max retries");
      }
    } finally {
      activeScans--;
    }
  }

  isProcessing = false;

  if (scanQueue.length > 0) {
    setImmediate(() => processScanQueue());
  }
}

async function processAiQueue(): Promise<void> {
  if (isAiProcessing) return;
  isAiProcessing = true;

  while (aiQueue.length > 0 && activeAiJobs < MAX_CONCURRENT_AI) {
    const job = aiQueue.shift();
    if (!job) break;
    activeAiJobs++;

    try {
      queueEvents.emit("ai:started", { type: job.type, activeAiJobs });
      logger.info({ type: job.type }, "Processing AI job from queue");

      if (job.type === "auto-triage" && job.scanId) {
        try {
          const { default: OpenAI } = await import("openai");
          const openai = new OpenAI({
            apiKey: process.env["OPENCODE_API_KEY"] ?? "",
            baseURL: process.env["OPENCODE_API_BASE"] ?? "https://opencode.ai/zen/v1",
            timeout: 60000,
          });
          const model = process.env["OPENCODE_MODEL"] ?? "nemotron-3-super-free";
          const findingId = job.findingId;
          let query: Record<string, unknown> = {};
          if (findingId) {
            const { ObjectId } = await import("mongodb");
            query = { _id: new ObjectId(findingId) };
          }
          const findings = await col("findings").find(query).limit(5).toArray() as Array<Record<string, unknown>>;
          for (const finding of findings) {
            try {
              const prompt = `You are a security triage expert. Given this vulnerability finding, respond with ONLY a JSON object with two fields: "suggested_severity" (one of: critical, high, medium, low, info) and "confidence_score" (0.0 to 1.0). No explanation. Title: ${finding["title"]} Category: ${finding["category"]} Description: ${String(finding["description"] ?? "").slice(0, 200)}`;
              const completion = await openai.chat.completions.create({ model, max_tokens: 100, messages: [{ role: "user", content: prompt }], stream: false });
              const text = completion.choices[0]?.message?.content ?? "{}";
              const json = JSON.parse(text.trim()) as { suggested_severity?: string; confidence_score?: number };
              await col("findings").updateOne(
                { _id: finding["_id"] } as Record<string, unknown>,
                { $set: { ai_suggested_severity: json.suggested_severity, ai_confidence: json.confidence_score } }
              );
            } catch { /* skip individual */ }
          }
        } catch { /* AI not available */ }
      }

      queueEvents.emit("ai:completed", { type: job.type, activeAiJobs: activeAiJobs - 1 });
    } catch (err) {
      logger.error({ err, type: job.type }, "AI job failed");
      queueEvents.emit("ai:failed", { type: job.type });
    } finally {
      activeAiJobs--;
    }
  }

  isAiProcessing = false;
  if (aiQueue.length > 0) setImmediate(() => processAiQueue());
}

setInterval(() => {
  if (scanQueue.length > 0 && !isProcessing) processScanQueue();
  if (aiQueue.length > 0 && !isAiProcessing) processAiQueue();
}, 5000);

logger.info("Queue system initialized (memory-backed, max scans=%d, max AI=%d)", MAX_CONCURRENT_SCANS, MAX_CONCURRENT_AI);
