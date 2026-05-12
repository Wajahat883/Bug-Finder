import { ObjectId } from "mongodb";
import { col } from "../../lib/db";
import { logger } from "../../lib/logger";

export async function runAttackSurfaceMonitorForTarget(targetId: string, targetUrl: string): Promise<void> {
  try {
    logger.info({ targetId, targetUrl }, "Running attack surface monitor for target");

    // Get previous state
    const target = (await col("targets").findOne({ _id: new ObjectId(targetId) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!target) return;

    const prevSubdomains = new Set<string>((target["monitored_subdomains"] as string[]) ?? []);
    const prevPorts = new Set<string>((target["monitored_ports"] as string[]) ?? []);

    // Get previous findings for subdomains and ports
    const prevFindings = (await col("findings")
      .find({ target_url: targetUrl, category: { $in: ["Subdomain", "Open Port", "Attack Surface Change"] } } as Record<string, unknown>)
      .toArray()) as Array<Record<string, unknown>>;

    // Extract known subdomains from findings
    const knownSubdomains = new Set<string>();
    const knownPorts = new Set<string>();
    for (const f of prevFindings) {
      if (String(f["category"]) === "Subdomain") knownSubdomains.add(String(f["title"] ?? ""));
      if (String(f["category"]) === "Open Port") knownPorts.add(String(f["endpoint"] ?? ""));
    }

    // Combine with stored monitored state
    for (const s of prevSubdomains) knownSubdomains.add(s);
    for (const p of prevPorts) knownPorts.add(p);

    // Run lightweight DNS check
    let currentSubdomains: string[] = [];
    let currentPorts: string[] = [];

    try {
      const { runSubdomainEnum } = await import("../scanner/subdomains");
      const events: Array<Record<string, unknown>> = [];
      const mockCtx = {
        targetUrl,
        profile: "quick" as const,
        emit: (e: Record<string, unknown>) => events.push(e),
        discoveredEndpoints: new Set<string>(),
        cancelled: false,
      };
      const subFindings = await runSubdomainEnum(mockCtx as never);
      currentSubdomains = subFindings.map((f) => String(f.endpoint ?? "")).filter(Boolean);
    } catch {
      // Scanner may not be available in all environments
    }

    try {
      const { runPortScan } = await import("../scanner/ports");
      const mockCtx = {
        targetUrl,
        profile: "quick" as const,
        emit: () => {},
        discoveredEndpoints: new Set<string>(),
        cancelled: false,
      };
      const portFindings = await runPortScan(mockCtx as never);
      currentPorts = portFindings.map((f) => String(f.endpoint ?? "")).filter(Boolean);
    } catch {
      // Scanner may not be available
    }

    const now = new Date();
    const newSubdomains = currentSubdomains.filter((s) => !knownSubdomains.has(s));
    const newPorts = currentPorts.filter((p) => !knownPorts.has(p));

    // Create findings for new surface changes
    const changes: Array<Record<string, unknown>> = [];

    for (const subdomain of newSubdomains) {
      changes.push({
        title: `New Subdomain Detected: ${subdomain}`,
        category: "Attack Surface Change",
        severity: "medium",
        endpoint: subdomain,
        target_url: targetUrl,
        description: `A new subdomain (${subdomain}) was detected that was not present in the previous attack surface scan. New subdomains may introduce new attack vectors.`,
        evidence: `Subdomain: ${subdomain}\nDetected at: ${now.toISOString()}`,
        recommended_fix: "Review the new subdomain. Ensure it has proper security controls, is patched, and does not expose sensitive services.",
        cvss_score: 5.3,
        cwe_id: "CWE-200",
        scanner_name: "AttackSurfaceMonitor",
        scanner_family: "recon",
        confidence: 0.85,
        created_at: now,
        updated_at: now,
        validation_status: "needs_review",
      });
    }

    for (const port of newPorts) {
      changes.push({
        title: `New Open Port Detected: ${port}`,
        category: "Attack Surface Change",
        severity: "medium",
        endpoint: port,
        target_url: targetUrl,
        description: `A new open port (${port}) was detected that was not present in the previous attack surface scan. New open ports may expose previously hidden services.`,
        evidence: `Port: ${port}\nDetected at: ${now.toISOString()}`,
        recommended_fix: "Verify the necessity of this port. If not required, close it. If required, ensure the service is patched and properly configured.",
        cvss_score: 5.3,
        cwe_id: "CWE-200",
        scanner_name: "AttackSurfaceMonitor",
        scanner_family: "recon",
        confidence: 0.85,
        created_at: now,
        updated_at: now,
        validation_status: "needs_review",
      });
    }

    if (changes.length > 0) {
      await col("findings").insertMany(changes);

      // Create activity event
      await col("activity_events").insertOne({
        type: "surface_change",
        message: `Attack surface changed: ${newSubdomains.length} new subdomains, ${newPorts.length} new ports detected for ${targetUrl}`,
        timestamp: now,
        target_url: targetUrl,
        severity: "medium",
      });

      logger.info({ targetId, newSubdomains: newSubdomains.length, newPorts: newPorts.length }, "Attack surface changes detected");
    }

    // Update target with new monitored state
    await col("targets").updateOne(
      { _id: new ObjectId(targetId) } as Record<string, unknown>,
      {
        $set: {
          last_monitored: now,
          monitored_subdomains: currentSubdomains,
          monitored_ports: currentPorts,
          updated_at: now,
        },
      }
    );
  } catch (err) {
    logger.error({ err, targetId }, "Attack surface monitor error");
  }
}

export async function runAttackSurfaceMonitor(): Promise<void> {
  try {
    const targets = (await col("targets").find({ status: "active" } as Record<string, unknown>).toArray()) as Array<Record<string, unknown>>;
    logger.info({ count: targets.length }, "Running attack surface monitor for all targets");
    for (const target of targets) {
      await runAttackSurfaceMonitorForTarget(String(target["_id"]), String(target["url"] ?? ""));
    }
    logger.info("Attack surface monitor complete");
  } catch (err) {
    logger.error({ err }, "Attack surface monitor batch error");
  }
}
