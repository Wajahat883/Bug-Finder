import { logger } from "../lib/logger";
import { col, ObjectId } from "../lib/db";
import { enqueueScan } from "../services/queue/manager";

export async function verifyPatch(remediationId: string): Promise<{ verified: boolean; message: string }> {
  try {
    const remediation = await col("remediations").findOne({
      _id: new ObjectId(remediationId),
    } as Record<string, unknown>) as Record<string, unknown> | null;

    if (!remediation) {
      return { verified: false, message: "Remediation not found" };
    }

    const findingId = remediation["finding_id"];
    if (!findingId) {
      return { verified: false, message: "No linked finding for patch verification" };
    }

    const finding = await col("findings").findOne({
      _id: findingId,
    } as Record<string, unknown>) as Record<string, unknown> | null;

    if (!finding) {
      return { verified: false, message: "Source finding not found" };
    }

    const targetUrl = String(finding["target_url"] ?? "");
    const endpoint = String(finding["endpoint"] ?? "");

    if (!targetUrl) {
      return { verified: false, message: "No target URL to verify against" };
    }

    const scanTarget = endpoint ? new URL(endpoint).origin : targetUrl;

    logger.info({ remediationId, targetUrl: scanTarget, finding: finding["title"] }, "Running patch verification scan");

    const jobId = new ObjectId().toHexString();

    await col("scan_jobs").insertOne({
      _id: new ObjectId(jobId),
      target_url: scanTarget,
      scan_profile: "standard",
      status: "queued",
      progress: 0,
      created_at: new Date(),
      triggered_by: "patch-verification",
      remediation_id: remediationId,
      finding_id: String(finding["_id"]),
    });

    await enqueueScan({
      jobId,
      targetUrl: scanTarget,
      profile: "standard",
      validationEnabled: true,
      fuzzingEnabled: false,
      bugBountyMode: false,
    });

    await col("remediations").updateOne(
      { _id: new ObjectId(remediationId) } as Record<string, unknown>,
      { $set: { verification_scan_id: jobId, verification_status: "in_progress", verification_started_at: new Date() } }
    );

    return { verified: false, message: `Verification scan queued (${jobId})` };
  } catch (err) {
    logger.error({ err, remediationId }, "Patch verification error");
    return { verified: false, message: "Verification failed" };
  }
}

export async function checkVerificationResult(scanJobId: string): Promise<void> {
  try {
    const scan = await col("scan_jobs").findOne({
      _id: new ObjectId(scanJobId),
    } as Record<string, unknown>) as Record<string, unknown> | null;

    if (!scan || scan["status"] !== "completed") return;

    const remediationId = scan["remediation_id"] as string | undefined;
    const findingId = scan["finding_id"] as string | undefined;

    if (!remediationId || !findingId) return;

    const originalTitle = await col("findings").findOne({
      _id: new ObjectId(findingId),
    } as Record<string, unknown>).then(f => String((f as Record<string, unknown>)?.["title"] ?? ""));

    const relatedFindings = await col("findings").find({
      scan_job_id: new ObjectId(scanJobId),
      title: originalTitle,
    } as Record<string, unknown>).toArray() as Array<Record<string, unknown>>;

    const stillExists = relatedFindings.length > 0;
    const wasResolved = !stillExists;

    await col("remediations").updateOne(
      { _id: new ObjectId(remediationId) } as Record<string, unknown>,
      {
        $set: {
          verification_status: wasResolved ? "verified" : "failed",
          verification_completed_at: new Date(),
          verification_result: wasResolved ? "Patch confirmed — finding no longer detected" : "Patch failed — finding still present",
        },
      }
    );

    if (wasResolved) {
      await col("findings").updateOne(
        { _id: new ObjectId(findingId) } as Record<string, unknown>,
        { $set: { resolved_at: new Date(), validation_status: "resolved" } }
      );
      logger.info({ findingId, remediationId }, "Patch verified — finding resolved");
    } else {
      logger.warn({ findingId, remediationId }, "Patch verification failed — finding still exists");
    }
  } catch (err) {
    logger.error({ err, scanJobId }, "Verification check error");
  }
}
