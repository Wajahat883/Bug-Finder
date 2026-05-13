import { Router } from "express";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

const router = Router();

// GET /api/version — Current API version info
router.get("/api/version", (_req, res) => {
  res.json({
    version: "1.0.0",
    api_version: "v1",
    stable: true,
    deprecated_endpoints: [],
    changelog: "/api/version/changelog",
  });
});

// Legacy route compatibility fallback
const knownLegacyPaths: Record<string, string> = {
  "/scan-jobs": "/v1/scan-jobs",
  "/findings": "/v1/findings",
  "/targets": "/v1/targets",
  "/remediations": "/v1/remediations",
  "/scans": "/v1/scan-jobs",
};

export default router;
