import express, { type Express } from "express";
import cors from "cors";
import helmet from "helmet";
import session from "express-session";
import MongoStore from "connect-mongo";
import pinoHttp from "pino-http";
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
}));

// POINT 2: CORS — allow configured origins, never throw (return 403 instead)
const allowedOrigins = (process.env["ALLOWED_ORIGINS"] ?? "")
  .split(",").map(o => o.trim()).filter(Boolean);

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return { id: req.id, method: req.method, url: req.url?.split("?")[0] };
      },
      res(res) {
        return { statusCode: res.statusCode };
      },
    },
  }),
);

app.use(cors({
  origin: (origin, cb) => {
    // No origin = same-origin request or server-to-server — always allow
    if (!origin) return cb(null, true);
    // In dev (no ALLOWED_ORIGINS set) — allow all origins so frontend works on any port
    if (allowedOrigins.length === 0) return cb(null, true);
    // In prod — only allow explicitly listed origins
    if (allowedOrigins.includes(origin)) return cb(null, true);
    // Blocked — return null (no CORS headers) not an Error (which crashes response)
    return cb(null, false);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-API-Key", "X-Correlation-ID"],
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

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// API key auth runs before routes — sets session if valid key provided
app.use("/api", apiKeyAuth);
app.use(ipAllowlistMiddleware);
app.use("/api", globalLimiter);
// Multi-tenant context injection — runs before all API routes
app.use("/api", tenantMiddleware);
app.use("/api", router);

app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error({ err }, "Unhandled error");
  res.status(500).json({ error: isProdMode ? "Internal server error" : err.message });
});

export default app;
