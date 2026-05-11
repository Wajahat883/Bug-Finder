import cron from "node-cron";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { runScanPipeline } from "./scanner/index";
import { sendReportEmail, type ReportData } from "./email";

interface ScheduledScan {
  _id: ObjectId;
  target_url: string;
  scan_profile: string;
  cron_expression: string;
  enabled: boolean;
  last_run?: Date;
  next_run?: Date;
  validation_enabled: boolean;
  fuzzing_enabled: boolean;
  bug_bounty_mode: boolean;
}

const activeTasks = new Map<string, cron.ScheduledTask>();

export async function initScheduler() {
  const scheduled = await col("scheduled_scans").find({ enabled: true }).toArray() as ScheduledScan[];
  for (const s of scheduled) {
    scheduleJob(s);
  }

  // SLA enforcement: check every hour for breached remediations
  cron.schedule("0 * * * *", async () => {
    try {
      await checkSlaBreaches();
    } catch (err) {
      logger.error({ err }, "SLA check error");
    }
  });

  logger.info({ count: scheduled.length }, "Scheduler initialized");
  await initReportSchedules();
}

async function checkSlaBreaches() {
  const SLA_DAYS: Record<string, number> = { critical: 1, high: 7, medium: 30, low: 90 };
  const now = new Date();

  for (const [severity, days] of Object.entries(SLA_DAYS)) {
    const cutoff = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);

    // Find remediations that are overdue and not yet flagged
    const overdue = await col("remediations").find({
      status: { $in: ["pending", "in_progress"] },
      created_at: { $lt: cutoff },
      sla_severity: severity,
      sla_breached: { $ne: true },
    } as Record<string, unknown>).toArray() as Array<Record<string, unknown>>;

    if (overdue.length === 0) continue;

    // Mark them as breached
    const ids = overdue.map((r) => r["_id"] as ObjectId);
    await col("remediations").updateMany(
      { _id: { $in: ids } } as Record<string, unknown>,
      { $set: { sla_breached: true, sla_breached_at: now } }
    );

    logger.warn({ severity, count: overdue.length }, "SLA breach detected");

    // Send Slack alert for critical/high breaches
    if ((severity === "critical" || severity === "high") && process.env["SLACK_WEBHOOK_URL"]) {
      const webhook = process.env["SLACK_WEBHOOK_URL"];
      const targets = [...new Set(overdue.map((r) => String(r["target_url"] ?? "unknown")))].slice(0, 3);
      await fetch(webhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: `:alarm_clock: *SLA BREACH — Bug Finder Pro*`,
          attachments: [{
            color: severity === "critical" ? "danger" : "warning",
            fields: [
              { title: "Severity", value: severity.toUpperCase(), short: true },
              { title: "Overdue Count", value: String(overdue.length), short: true },
              { title: "SLA Limit", value: `${days} day${days !== 1 ? "s" : ""}`, short: true },
              { title: "Affected Targets", value: targets.join(", "), short: false },
            ],
            footer: "Bug Finder Pro SLA Monitor",
          }],
        }),
      }).catch(() => {});
    }
  }
}

export function scheduleJob(scan: ScheduledScan) {
  const id = String(scan._id);
  const existing = activeTasks.get(id);
  if (existing) existing.stop();

  if (!cron.validate(scan.cron_expression)) {
    logger.warn({ id, expr: scan.cron_expression }, "Invalid cron expression");
    return;
  }

  const task = cron.schedule(scan.cron_expression, async () => {
    logger.info({ id, target: scan.target_url }, "Running scheduled scan");
    try {
      const now = new Date();
      const insert = await col("scan_jobs").insertOne({
        target_url: scan.target_url,
        scan_profile: scan.scan_profile,
        status: "queued",
        progress: 0,
        created_at: now,
        started_at: null,
        completed_at: null,
        findings_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        risk_score: 0,
        ai_summary: null,
        validation_enabled: scan.validation_enabled,
        fuzzing_enabled: scan.fuzzing_enabled,
        bug_bounty_mode: scan.bug_bounty_mode,
        authorization_acknowledged: true,
        scanner_engines: [],
        error_message: null,
        scheduled_by: id,
      });

      await col("scheduled_scans").updateOne(
        { _id: scan._id } as Record<string, unknown>,
        { $set: { last_run: now } }
      );

      runScanPipeline({
        jobId: String(insert.insertedId),
        targetUrl: scan.target_url,
        profile: scan.scan_profile as "quick" | "standard" | "deep",
        validationEnabled: scan.validation_enabled,
        fuzzingEnabled: scan.fuzzing_enabled,
        bugBountyMode: scan.bug_bounty_mode,
      }).catch((err) => logger.error({ err }, "Scheduled scan pipeline error"));
    } catch (err) {
      logger.error({ err }, "Scheduled scan trigger error");
    }
  });

  activeTasks.set(id, task);
}

export function unscheduleJob(id: string) {
  const task = activeTasks.get(id);
  if (task) { task.stop(); activeTasks.delete(id); }
}

// ── Report schedules ──────────────────────────────────────────────────────

interface ReportSchedule {
  _id: ObjectId;
  name: string;
  recipients: string[];
  cron_expression: string;
  target_url?: string;
  enabled: boolean;
}

const reportTasks = new Map<string, cron.ScheduledTask>();

export async function initReportSchedules() {
  const schedules = await col("report_schedules").find({ enabled: true }).toArray() as ReportSchedule[];
  for (const s of schedules) scheduleReport(s);
  logger.info({ count: schedules.length }, "Report schedules initialized");
}

export function scheduleReport(schedule: ReportSchedule) {
  const id = String(schedule._id);
  const existing = reportTasks.get(id);
  if (existing) existing.stop();

  if (!cron.validate(schedule.cron_expression)) {
    logger.warn({ id, expr: schedule.cron_expression }, "Invalid report cron expression");
    return;
  }

  const task = cron.schedule(schedule.cron_expression, async () => {
    logger.info({ id, name: schedule.name }, "Sending scheduled report");
    try {
      const filter: Record<string, unknown> = schedule.target_url
        ? { target_url: schedule.target_url }
        : {};

      const findings = await col("findings").find(filter).toArray() as Array<Record<string, unknown>>;
      const remediations = await col("remediations").find(filter).toArray() as Array<Record<string, unknown>>;

      const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

      const report: ReportData = {
        title: schedule.name,
        generatedAt: new Date(),
        targetUrl: schedule.target_url,
        totalFindings: findings.length,
        critical: findings.filter((f) => f["severity"] === "critical").length,
        high: findings.filter((f) => f["severity"] === "high").length,
        medium: findings.filter((f) => f["severity"] === "medium").length,
        low: findings.filter((f) => f["severity"] === "low").length,
        topFindings: findings
          .sort((a, b) => {
            const order = ["critical", "high", "medium", "low", "info"];
            return order.indexOf(String(a["severity"])) - order.indexOf(String(b["severity"]));
          })
          .slice(0, 10)
          .map((f) => ({
            title: String(f["title"] ?? ""),
            severity: String(f["severity"] ?? "medium"),
            endpoint: String(f["endpoint"] ?? ""),
          })),
        openRemediations: remediations.filter((r) => r["status"] !== "resolved").length,
        resolvedLastPeriod: remediations.filter(
          (r) => r["status"] === "resolved" && new Date(r["updated_at"] as string) > sevenDaysAgo
        ).length,
      };

      await sendReportEmail(schedule.recipients, report);
      await col("report_schedules").updateOne(
        { _id: schedule._id } as Record<string, unknown>,
        { $set: { last_sent: new Date() } }
      );
    } catch (err) {
      logger.error({ err }, "Scheduled report send error");
    }
  });

  reportTasks.set(id, task);
}

export function unscheduleReport(id: string) {
  const task = reportTasks.get(id);
  if (task) { task.stop(); reportTasks.delete(id); }
}
