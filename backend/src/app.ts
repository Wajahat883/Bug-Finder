import express, { type Express } from "express";
import cors from "cors";
import session from "express-session";
import MongoStore from "connect-mongo";
import pinoHttp from "pino-http";
import router from "./routes";
import { logger } from "./lib/logger";
import { connectDb } from "./lib/db";
import { seedData } from "./lib/seed";
import { apiKeyAuth } from "./middlewares/apikey";
import { ipAllowlistMiddleware } from "./middlewares/ip-allowlist";
import { initScheduler } from "./services/scheduler";

const app: Express = express();

connectDb()
  .then(() => seedData())
  .then(() => initScheduler())
  .catch((err) => logger.warn({ err }, "DB init/seed error — continuing without database"));

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

app.use(cors({ origin: true, credentials: true }));

app.set("trust proxy", 1);
app.use(
  session({
    name: "bbp.sid",
    secret: process.env["SESSION_SECRET"] ?? "bug-finder-secret-change-in-prod",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env["MONGODB_URI"] ?? "mongodb://bugfinder:password123@mongodb:27017/bugfinder?authSource=admin",
      collectionName: "sessions",
      ttl: 7 * 24 * 60 * 60,
    }),
    cookie: {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// API key auth runs before routes — sets session if valid key provided
app.use("/api", apiKeyAuth);
app.use(ipAllowlistMiddleware);
app.use("/api", router);

export default app;
