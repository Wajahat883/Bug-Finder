import { Router } from "express";
const router = Router();
router.get("/openapi.json", (req, res) => {
  res.json({
    openapi: "3.0.3",
    info: { title: "Bug Finder Pro API", version: "1.0.0", description: "Enterprise Security Scanning Platform" },
    servers: [{ url: "/api" }],
    security: [{ bearerAuth: [] }],
    components: { securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } } },
    paths: {
      "/scans": { get: { summary: "List scans", tags: ["Scans"], responses: { "200": { description: "Array of scan jobs" } } }, post: { summary: "Start scan", tags: ["Scans"], responses: { "201": { description: "Scan created" } } } },
      "/findings": { get: { summary: "List findings", tags: ["Findings"], parameters: [{ name: "severity", in: "query", schema: { type: "string", enum: ["critical","high","medium","low"] } }, { name: "status", in: "query", schema: { type: "string" } }], responses: { "200": { description: "Paginated findings" } } } },
      "/targets": { get: { summary: "List targets", tags: ["Targets"], responses: { "200": { description: "Array of targets" } } }, post: { summary: "Add target", tags: ["Targets"], responses: { "201": { description: "Target created" } } } },
      "/analytics/metrics/executive": { get: { summary: "Executive metrics", tags: ["Analytics"], responses: { "200": { description: "KPI metrics" } } } },
      "/analytics/anomalies": { get: { summary: "Anomaly detection", tags: ["Analytics"], responses: { "200": { description: "List of anomalies" } } } },
      "/sbom/{scanId}": { get: { summary: "Get SBOM", tags: ["SBOM"], parameters: [{ name: "scanId", in: "path", required: true, schema: { type: "string" } }], responses: { "200": { description: "CycloneDX SBOM" } } } },
    }
  });
});
export default router;
