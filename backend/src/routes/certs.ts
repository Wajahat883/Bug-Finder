import { Router } from "express";
import { ObjectId } from "mongodb";
import tls from "tls";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

interface CertInfo {
  domain: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  status: "valid" | "expiring_soon" | "expired" | "error";
  subjectAltNames: string[];
  protocol: string;
  cipher: string;
}

async function checkDomainCert(domain: string): Promise<CertInfo> {
  return new Promise((resolve) => {
    try {
      const socket = tls.connect({ host: domain, port: 443, servername: domain, rejectUnauthorized: false, timeout: 10000 }, () => {
        const cert = socket.getPeerCertificate();
        const cipher = socket.getCipher();
        socket.end();

        if (!cert || !cert.valid_to) {
          resolve({ domain, issuer: "Unknown", validFrom: "", validTo: "", daysRemaining: 0, status: "error", subjectAltNames: [], protocol: "", cipher: "" });
          return;
        }

        const validTo = new Date(cert.valid_to);
        const daysRemaining = Math.ceil((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
        const status = daysRemaining < 0 ? "expired" : daysRemaining < 30 ? "expiring_soon" : "valid";

        resolve({
          domain,
          issuer: String(cert.issuer?.O ?? cert.issuer?.CN ?? "Unknown"),
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          daysRemaining,
          status,
          subjectAltNames: cert.subjectaltname?.split(",").map((s: string) => s.trim().replace("DNS:", "")) ?? [],
          protocol: cipher?.version ?? "",
          cipher: cipher?.name ?? "",
        });
      });

      socket.on("error", () => {
        resolve({ domain, issuer: "Unknown", validFrom: "", validTo: "", daysRemaining: 0, status: "error", subjectAltNames: [], protocol: "", cipher: "" });
      });

      socket.on("timeout", () => {
        socket.destroy();
        resolve({ domain, issuer: "Unknown", validFrom: "", validTo: "", daysRemaining: 0, status: "error", subjectAltNames: [], protocol: "", cipher: "" });
      });
    } catch {
      resolve({ domain, issuer: "Unknown", validFrom: "", validTo: "", daysRemaining: 0, status: "error", subjectAltNames: [], protocol: "", cipher: "" });
    }
  });
}

// GET /certs/check/:targetId — Check SSL cert for a target
router.get("/certs/check/:targetId", requireAuth, async (req, res) => {
  try {
    const target = await col("targets").findOne({ _id: new ObjectId(String(req.params.targetId)) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!target) return res.status(404).json({ error: "Target not found" });
    const domain = String(target["domain"] ?? "");
    if (!domain) return res.status(400).json({ error: "No domain" });

    const certInfo = await checkDomainCert(domain);
    await col("cert_checks").insertOne({ ...certInfo, target_id: req.params.targetId, checked_at: new Date() });
    res.json(certInfo);
  } catch (err) {
    res.status(500).json({ error: "SSL check failed" });
  }
});

// GET /certs/status — Get cert status for all targets
router.get("/certs/status", requireAuth, async (_req, res) => {
  try {
    const targets = await col("targets").find({ status: "active" }).toArray() as Array<Record<string, unknown>>;
    const results = await Promise.all(targets.map(async (t) => {
      const domain = String(t["domain"] ?? "");
      if (!domain) return null;
      const lastCheck = await col("cert_checks").findOne(
        { target_id: String(t["_id"]) } as Record<string, unknown>,
        { sort: { checked_at: -1 } }
      ) as Record<string, unknown> | null;
      if (lastCheck && (Date.now() - new Date(lastCheck["checked_at"] as string).getTime()) < 3600000) {
        return { target_id: String(t["_id"]), domain, ...lastCheck, cached: true };
      }
      const info = await checkDomainCert(domain);
      await col("cert_checks").insertOne({ ...info, target_id: String(t["_id"]), checked_at: new Date() });
      return { target_id: String(t["_id"]), ...info };
    }));
    res.json(results.filter(Boolean));
  } catch (err) {
    logger.error({ err }, "Cert status error");
    res.status(500).json({ error: "SSL status check failed" });
  }
});

export default router;
