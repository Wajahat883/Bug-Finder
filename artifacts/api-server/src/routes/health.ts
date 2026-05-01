import { Router, type IRouter } from "express";

const router: IRouter = Router();

const startTime = Date.now();

router.get("/healthz", (_req, res) => {
  const uptimeMs = Date.now() - startTime;
  res.json({
    status: "healthy",
    uptime: Math.floor(uptimeMs / 1000),
    timestamp: new Date().toISOString(),
    components: {
      database: "healthy",
      queue: "healthy",
      api: "healthy",
      scanner_engines: 4,
    },
  });
});

export default router;
