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

const app: Express = express();

connectDb()
  .then(() => seedData())
  .then(() => initScheduler())
  .catch((err) => logger.warn({ err }, "DB init/seed error — continuing without database"));

// POINT 2: CSP hardening via helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false, // allow SSE cross-origin in dev
}));

// POINT 2: CORS — only allow configured origins (not wildcard)
const allowedOrigins = (process.env["ALLOWED_ORIGINS"] ?? "http://localhost:3000,http://localhost:5173").split(",").map(o => o.trim());

// POINT 9: Correlation IDs on every request
app.use(correlationMiddleware);

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
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-API-Key", "X-Correlation-ID"],
}));

app.set("trust proxy", 1);
app.set("trust proxy", 1);
const isProd = process.env["NODE_ENV"] === "production";
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
      secure: isProd,
      sameSite: isProd ? "strict" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// API key auth runs before routes — sets session if valid key provided
app.use("/api", apiKeyAuth);
app.use(ipAllowlistMiddleware);
app.use("/api", globalLimiter);
app.use("/api", router);

app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error({ err }, "Unhandled error");
  res.status(500).json({ error: isProd ? "Internal server error" : err.message });
});

export default app;
