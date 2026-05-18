import express, { type Express } from "express";
import cors from "cors";
import helmet from "helmet";
import session from "express-session";
import MongoStore from "connect-mongo";
import pinoHttp from "pino-http";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import router from "./routes";
import { logger } from "./lib/logger";
import { connectDb } from "./lib/db";
import { seedData } from "./lib/seed";
import { apiKeyAuth } from "./middlewares/apikey";
import { ipAllowlistMiddleware } from "./middlewares/ip-allowlist";
import { globalLimiter } from "./middlewares/rate-limit";
import { correlationMiddleware } from "./middlewares/correlation";
import { initScheduler } from "./services/scheduler";
import { seedDefaultFlags } from "./lib/feature-flags";
import { tenantMiddleware } from "./middlewares/tenant";

const app: Express = express();

connectDb()
  .then(() => seedData())
  .then(() => seedDefaultFlags())
  .then(() => initScheduler())
  .catch((err) => logger.warn({ err }, "DB init/seed error — continuing without database"));

const isProdMode = process.env["NODE_ENV"] === "production";

// POINT 9: Correlation IDs on every request
app.use(correlationMiddleware);

// POINT 2: Security headers via helmet — only CSP-sensitive headers, no COEP that breaks SSE
app.use(helmet({
  contentSecurityPolicy: isProdMode ? {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  } : false,  // Disable CSP in dev — avoids blocking localhost cross-port requests
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
  // HSTS: 1 year, include subdomains, eligible for preload list
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}));

// POINT 2: CORS — allow configured origins, never throw (return 403 instead)
const allowedOrigins = (process.env["ALLOWED_ORIGINS"] ?? "")
  .split(",").map(o => o.trim()).filter(Boolean);

const REDACTED_HEADERS = ["authorization", "cookie", "x-api-key"];

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        // Redact sensitive headers before logging
        const safeHeaders: Record<string, string> = {};
        for (const [k, v] of Object.entries(req.headers as Record<string, string>)) {
          safeHeaders[k] = REDACTED_HEADERS.includes(k.toLowerCase()) ? "[REDACTED]" : v;
        }
        return { id: req.id, method: req.method, url: req.url?.split("?")[0], headers: safeHeaders };
      },
      res(res) {
        return { statusCode: res.statusCode };
      },
    },
  }),
);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowedOrigins.length === 0) {
      if (isProdMode) return cb(null, false);
      return cb(null, true);
    }
    if (allowedOrigins.includes(origin)) return cb(null, true);
    return cb(null, false);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-API-Key", "X-Correlation-ID", "X-CSRF-Token"],
}));

app.set("trust proxy", 1);
const sessionSecret = process.env["SESSION_SECRET"];
if (!sessionSecret) {
  logger.error("SESSION_SECRET env var is required");
  process.exit(1);
}

const mongoUrl = process.env["MONGODB_URI"] || process.env["MONGO_URI"];
if (!mongoUrl) {
  logger.error("MONGODB_URI or MONGO_URI env var is required for session store");
  process.exit(1);
}

app.use(
  session({
    name: "bbp.sid",
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl,
      collectionName: "sessions",
      ttl: 7 * 24 * 60 * 60,
    }),
    cookie: {
      httpOnly: true,
      secure: isProdMode,
      sameSite: isProdMode ? "strict" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
  })
);

app.use(cookieParser());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// CSRF: double-submit cookie pattern — sets __csrf cookie, validates X-CSRF-Token header on mutating requests
app.use("/api", (req, res, next) => {
  const skipMethods = ["GET", "HEAD", "OPTIONS"];
  const skipPaths = ["/api/auth/login", "/api/auth/register", "/api/auth/saml"];

  // Issue token on every request (SameSite=Lax already mitigates most CSRF, this adds defense-in-depth)
  if (!req.cookies?.["__csrf"]) {
    const token = crypto.randomBytes(24).toString("hex");
    res.cookie("__csrf", token, { httpOnly: false, sameSite: "strict", secure: isProdMode });
  }

  if (skipMethods.includes(req.method) || skipPaths.some(p => req.path.startsWith(p.replace("/api", "")))) {
    return next();
  }

  // API key requests bypass CSRF (machine-to-machine)
  if (req.headers["x-api-key"]) return next();

  // JSON requests are inherently CSRF-safe (browsers enforce CORS preflight for application/json)
  const contentType = (req.headers["content-type"] ?? "").toLowerCase();
  if (contentType.includes("application/json")) return next();

  const cookieToken = req.cookies?.["__csrf"];
  const headerToken = req.headers["x-csrf-token"];
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ type: "https://httpstatuses.com/403", title: "CSRF validation failed", status: 403 });
  }
  next();
});

// Rate-limit CORS preflight requests to prevent OPTIONS flood attacks
app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    return globalLimiter(req, res, next);
  }
  next();
});

// API key auth runs before routes — sets session if valid key provided
app.use("/api", apiKeyAuth);
app.use(ipAllowlistMiddleware);
app.use("/api", globalLimiter);
// Multi-tenant context injection — runs before all API routes
app.use("/api", tenantMiddleware);
app.use("/api", router);

// SLA breach enforcement — hourly background job
setInterval(async () => {
  try {
    const { col } = await import("./lib/db");
    const { SLA_DAYS } = await import("./routes/sla-enforcement");
    const now = new Date();
    let totalBreached = 0;
    for (const [severity, days] of Object.entries(SLA_DAYS)) {
      const deadline = new Date(now.getTime() - (days as number) * 86400000);
      const breached = await col("findings").find({
        severity, status: { $nin: ["resolved", "false_positive"] },
        created_at: { $lte: deadline }, sla_notified: { $ne: true },
      } as Record<string, unknown>).limit(50).toArray() as Array<Record<string, unknown>>;
      if (breached.length > 0) {
        await col("findings").updateMany(
          { _id: { $in: breached.map(f => f["_id"]) } } as Record<string, unknown>,
          { $set: { sla_notified: true, sla_breached_at: now } }
        );
        totalBreached += breached.length;
      }
    }
    if (totalBreached > 0) {
      const adminEmail = process.env["ADMIN_EMAIL"] ?? "";
      if (adminEmail) {
        const { sendEmail } = await import("./services/email");
        sendEmail({ to: adminEmail, subject: `[SLA Alert] ${totalBreached} finding(s) breached SLA`, html: `<p>${totalBreached} finding(s) have exceeded their SLA deadline. Log in to review them.</p>` }).catch(() => {});
      }
    }
  } catch { /* non-fatal */ }
}, 60 * 60 * 1000);

app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error({ err }, "Unhandled error");
  res.status(500).json({ error: isProdMode ? "Internal server error" : err.message });
});

export default app;
