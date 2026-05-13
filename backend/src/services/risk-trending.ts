import { col, ObjectId } from "../lib/db";
import { logger } from "../lib/logger";

interface RiskSnapshot {
  timestamp: Date;
  riskScore: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  totalFindings: number;
}

export async function captureRiskSnapshot(): Promise<RiskSnapshot | null> {
  try {
    const findings = await col("findings").find({ validation_status: { $ne: "false_positive" } }).toArray() as Array<Record<string, unknown>>;

    const critCount = findings.filter(f => f["severity"] === "critical").length;
    const highCount = findings.filter(f => f["severity"] === "high").length;
    const medCount = findings.filter(f => f["severity"] === "medium").length;
    const lowCount = findings.filter(f => f["severity"] === "low").length;

    const riskScore = Math.min(100, Math.round(critCount * 25 + highCount * 15 + medCount * 8 + lowCount * 3));

    const snapshot: RiskSnapshot = {
      timestamp: new Date(),
      riskScore,
      criticalCount: critCount,
      highCount,
      mediumCount: medCount,
      lowCount,
      totalFindings: findings.length,
    };

    await col("risk_snapshots").insertOne(snapshot);

    const lastSnapshot = await col("risk_snapshots").find({}).sort({ timestamp: -1 }).skip(1).limit(1).toArray() as Array<Record<string, unknown>>;
    if (lastSnapshot.length > 0) {
      const prev = lastSnapshot[0];
      const prevScore = Number(prev["riskScore"] ?? 0);
      const delta = riskScore - prevScore;

      if (delta >= 10) {
        logger.warn({ previousScore: prevScore, currentScore: riskScore, delta }, "Risk score increased significantly — possible regression");

        const { notifyAllChannels } = await import("./notifications");
        notifyAllChannels({
          title: `Risk Score Increased from ${prevScore} to ${riskScore} (+${delta})`,
          severity: delta >= 20 ? "critical" : "high",
          message: `Overall risk score has increased by ${delta} points. Critical findings: ${critCount}, High: ${highCount}. Review recent scans for regressions.`,
          riskScore,
        }).catch(() => {});
      }
    }

    return snapshot;
  } catch (err) {
    logger.error({ err }, "Failed to capture risk snapshot");
    return null;
  }
}

export async function getRiskTrend(days = 30): Promise<RiskSnapshot[]> {
  try {
    const cutoff = new Date(Date.now() - days * 86400000);
    const snapshots = await col("risk_snapshots")
      .find({ timestamp: { $gte: cutoff } })
      .sort({ timestamp: 1 })
      .toArray() as Array<Record<string, unknown>>;

    return snapshots.map(s => ({
      timestamp: new Date(String(s["timestamp"] ?? "")),
      riskScore: Number(s["riskScore"] ?? 0),
      criticalCount: Number(s["criticalCount"] ?? 0),
      highCount: Number(s["highCount"] ?? 0),
      mediumCount: Number(s["mediumCount"] ?? 0),
      lowCount: Number(s["lowCount"] ?? 0),
      totalFindings: Number(s["totalFindings"] ?? 0),
    }));
  } catch {
    return [];
  }
}

export async function checkForRegressions(): Promise<Array<{ title: string; endpoint: string; severity: string }>> {
  try {
    const recent = await col("findings")
      .find({ created_at: { $gte: new Date(Date.now() - 86400000) } })
      .toArray() as Array<Record<string, unknown>>;

    const wasResolved = await col("findings")
      .find({ validation_status: "resolved" })
      .toArray() as Array<Record<string, unknown>>;

    return wasResolved.filter(r => recent.some(n => String(n["title"]) === String(r["title"]))).map(r => ({
      title: String(r["title"]),
      endpoint: String(r["endpoint"] ?? ""),
      severity: "regression",
    }));
  } catch {
    return [];
  }
}

setInterval(() => {
  captureRiskSnapshot().catch(() => {});
}, 3600000); // Every hour

logger.info("Risk trending engine initialized (hourly snapshots)");
