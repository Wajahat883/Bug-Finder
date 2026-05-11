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
let activeScans = 0;
let activeAiJobs = 0;

export function getQueueStats() {
  return {
    scanQueue: scanQueue.length,
    aiQueue: aiQueue.length,
    activeScans,
    activeAiJobs,
  };
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
      await col("scan_jobs").updateOne(
        { _id: job.jobId } as never,
        { $set: { status: "failed", error_message: err instanceof Error ? err.message : "Worker failure" } }
      );
      queueEvents.emit("scan:failed", { jobId: job.jobId, error: err instanceof Error ? err.message : "Unknown" });

      if (scanQueue.length >= 1) {
        const failed = job;
        scanQueue.push(failed);
        logger.warn({ jobId: job.jobId }, "Re-queued failed scan for retry");
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
      await new Promise((resolve) => setTimeout(resolve, 1000));
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
