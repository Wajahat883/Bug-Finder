// POINT 4: Concurrency control via env-configurable limits
// POINT 5: Exponential backoff on retries
// POINT 6: Redis-backed queue (with in-memory fallback)
// POINT 10: Worker scaling via env vars
import { EventEmitter } from "events";
import { logger } from "../../lib/logger";
import { col } from "../../lib/db";
import { runScanPipeline } from "../scanner/index";

// POINT 10: All limits configurable via environment variables
const MAX_CONCURRENT_SCANS = parseInt(process.env["MAX_CONCURRENT_SCANS"] ?? "2");
const MAX_CONCURRENT_AI    = parseInt(process.env["MAX_CONCURRENT_AI"]    ?? "3");
const MAX_SCAN_RETRIES     = parseInt(process.env["MAX_SCAN_RETRIES"]     ?? "3");
const MAX_QUEUE_SIZE       = parseInt(process.env["MAX_QUEUE_SIZE"]       ?? "50");

// POINT 5: Exponential backoff — 2s, 4s, 8s between retries
function retryDelayMs(attempt: number): number {
  return Math.min(1000 * Math.pow(2, attempt), 30000);
}

interface ScanJob {
  jobId: string;
  targetUrl: string;
  profile: "quick" | "standard" | "deep";
  validationEnabled: boolean;
  fuzzingEnabled: boolean;
  bugBountyMode: boolean;
  sessionCookie?: string;
  authToken?: string;
  customHeaders?: Record<string, string>;
  scopeHosts?: string[];
  openapiSpecUrl?: string;
  retryCount?: number;
  enqueuedAt?: number;
}

interface AiJob {
  type: string;
  findingId?: string;
  scanId?: string;
  payload?: Record<string, unknown>;
}

export const queueEvents = new EventEmitter();

// POINT 6: Try Redis — fall back to in-memory
let redisClient: import("ioredis").Redis | null = null;

async function tryConnectRedis(): Promise<void> {
  const redisUrl = process.env["REDIS_URL"];
  if (!redisUrl) return;
  try {
    const { default: Redis } = await import("ioredis");
    const client = new Redis(redisUrl, {
      lazyConnect: true,
      connectTimeout: 3000,
      maxRetriesPerRequest: 1,
      enableReadyCheck: false,
    });
    await client.connect();
    await client.ping();
    redisClient = client;
    logger.info("Queue: connected to Redis — distributed mode active");
    redisClient.on("error", (err) => {
      logger.warn({ err }, "Redis error — falling back to in-memory queue");
      redisClient = null;
    });
  } catch (err) {
    logger.warn({ err }, "Redis unavailable — using in-memory queue");
  }
}

tryConnectRedis();

// In-memory fallback
const scanQueue: ScanJob[] = [];
const aiQueue: AiJob[] = [];
let activeScans = 0;
let activeAiJobs = 0;
let isProcessing = false;
let isAiProcessing = false;

const SCAN_QUEUE_KEY = "bfp:scan_queue";
const AI_QUEUE_KEY   = "bfp:ai_queue";

async function redisPush(key: string, job: unknown): Promise<void> {
  if (!redisClient) return;
  await redisClient.rpush(key, JSON.stringify(job));
}

async function redisPop(key: string): Promise<unknown | null> {
  if (!redisClient) return null;
  const raw = await redisClient.lpop(key);
  return raw ? JSON.parse(raw) : null;
}

async function redisQueueLen(key: string): Promise<number> {
  if (!redisClient) return 0;
  return redisClient.llen(key);
}

// POINT 4: Backpressure — reject when queue exceeds max size
export async function enqueueScan(job: ScanJob): Promise<{ ok: boolean; reason?: string }> {
  job.enqueuedAt = Date.now();
  if (redisClient) {
    const len = await redisQueueLen(SCAN_QUEUE_KEY);
    if (len >= MAX_QUEUE_SIZE) {
      logger.warn({ jobId: job.jobId, queueLen: len }, "Scan queue full — rejecting job (backpressure)");
      return { ok: false, reason: "Queue is full. Try again later." };
    }
    await redisPush(SCAN_QUEUE_KEY, job);
    logger.info({ jobId: job.jobId, mode: "redis" }, "Scan enqueued in Redis");
  } else {
    if (scanQueue.length >= MAX_QUEUE_SIZE) {
      logger.warn({ jobId: job.jobId, queueLen: scanQueue.length }, "Scan queue full — rejecting job (backpressure)");
      return { ok: false, reason: "Queue is full. Try again later." };
    }
    scanQueue.push(job);
    logger.info({ jobId: job.jobId, mode: "memory" }, "Scan enqueued in memory");
  }
  queueEvents.emit("scan:enqueued", { jobId: job.jobId });
  processScanQueue();
  return { ok: true };
}

export async function enqueueAiJob(job: AiJob): Promise<void> {
  if (redisClient) {
    await redisPush(AI_QUEUE_KEY, job);
  } else {
    aiQueue.push(job);
  }
  queueEvents.emit("ai:enqueued", { type: job.type });
  processAiQueue();
}

async function nextScanJob(): Promise<ScanJob | null> {
  if (redisClient) {
    const job = await redisPop(SCAN_QUEUE_KEY);
    return job as ScanJob | null;
  }
  return scanQueue.shift() ?? null;
}

async function scanQueueLength(): Promise<number> {
  if (redisClient) return redisQueueLen(SCAN_QUEUE_KEY);
  return scanQueue.length;
}

async function processScanQueue(): Promise<void> {
  if (isProcessing) return;
  isProcessing = true;

  while ((await scanQueueLength()) > 0 && activeScans < MAX_CONCURRENT_SCANS) {
    const job = await nextScanJob();
    if (!job) break;
    activeScans++;
    queueEvents.emit("scan:started", { jobId: job.jobId, activeScans });

    // Run in background — don't await so loop continues for next slot
    runOneScan(job).finally(() => {
      activeScans--;
      queueEvents.emit("scan:slot_freed", { activeScans });
      processScanQueue();
    });
  }

  isProcessing = false;
}

async function runOneScan(job: ScanJob): Promise<void> {
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
      sessionCookie: job.sessionCookie,
      authToken: job.authToken,
      customHeaders: job.customHeaders,
      scopeHosts: job.scopeHosts,
      openapiSpecUrl: job.openapiSpecUrl,
    });

    logger.info({ jobId: job.jobId }, "Scan completed");
    queueEvents.emit("scan:completed", { jobId: job.jobId });
  } catch (err) {
    const attempt = (job.retryCount ?? 0) + 1;
    logger.error({ err, jobId: job.jobId, attempt }, "Scan failed");

    if (attempt <= MAX_SCAN_RETRIES) {
      // POINT 5: Exponential backoff before re-queue
      const delay = retryDelayMs(attempt);
      logger.warn({ jobId: job.jobId, attempt, delayMs: delay }, "Retrying scan with backoff");
      await new Promise(r => setTimeout(r, delay));
      job.retryCount = attempt;
      await enqueueScan(job);
    } else {
      await col("scan_jobs").updateOne(
        { _id: job.jobId } as never,
        { $set: { status: "failed", error_message: `Failed after ${MAX_SCAN_RETRIES} retries: ${err instanceof Error ? err.message : "unknown"}` } }
      );
      queueEvents.emit("scan:failed", { jobId: job.jobId });
    }
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
      queueEvents.emit("ai:started", { type: job.type });
      if (job.type === "auto-triage" && job.scanId) {
        try {
          const { default: OpenAI } = await import("openai");
          const openai = new OpenAI({
            apiKey: process.env["OPENCODE_API_KEY"] ?? "",
            baseURL: process.env["OPENCODE_API_BASE"] ?? "https://opencode.ai/zen/v1",
            timeout: 60000,
          });
          const model = process.env["OPENCODE_MODEL"] ?? "nemotron-3-super-free";
          const findings = await col("findings").find({}).limit(5).toArray() as Array<Record<string, unknown>>;
          for (const finding of findings) {
            try {
              const prompt = `Triage this vulnerability. Respond ONLY with JSON: {"suggested_severity":"critical|high|medium|low|info","confidence_score":0.0-1.0}. Title: ${finding["title"]} Category: ${finding["category"]}`;
              const completion = await openai.chat.completions.create({ model, max_tokens: 100, messages: [{ role: "user", content: prompt }], stream: false });
              const json = JSON.parse(completion.choices[0]?.message?.content ?? "{}") as { suggested_severity?: string; confidence_score?: number };
              await col("findings").updateOne({ _id: finding["_id"] } as Record<string, unknown>, { $set: { ai_suggested_severity: json.suggested_severity, ai_confidence: json.confidence_score } });
            } catch { /* skip individual */ }
          }
        } catch { /* AI not available */ }
      }
      queueEvents.emit("ai:completed", { type: job.type });
    } catch (err) {
      logger.error({ err, type: job.type }, "AI job failed");
    } finally {
      activeAiJobs--;
    }
  }

  isAiProcessing = false;
  if (aiQueue.length > 0) setImmediate(() => processAiQueue());
}

// Health watchdog — re-triggers queue processing every 5s in case events are missed
setInterval(() => {
  scanQueueLength().then(len => { if (len > 0 && !isProcessing) processScanQueue(); });
  if (aiQueue.length > 0 && !isAiProcessing) processAiQueue();
}, 5000);

// Queue stats for health endpoint
export async function getQueueStats(): Promise<{ scan_queued: number; ai_queued: number; active_scans: number; active_ai: number; max_scans: number; max_ai: number; mode: string }> {
  const scanQueued = await scanQueueLength();
  return {
    scan_queued: scanQueued,
    ai_queued: aiQueue.length,
    active_scans: activeScans,
    active_ai: activeAiJobs,
    max_scans: MAX_CONCURRENT_SCANS,
    max_ai: MAX_CONCURRENT_AI,
    mode: redisClient ? "redis" : "memory",
  };
}

logger.info({ maxScans: MAX_CONCURRENT_SCANS, maxAi: MAX_CONCURRENT_AI, maxQueue: MAX_QUEUE_SIZE }, "Queue system initialized");
