import { Router } from "express";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

const router = Router();

// Simple dev authentication — accepts admin/admin for demo
router.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body as { username?: string; password?: string };
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    // Demo: accept any credentials for now
    const token = `demo_${Math.random().toString(36).substring(2)}`;
    const user = {
      id: "user_wajahat883",
      github_login: username === "admin" ? "Wajahat883" : username,
      role: "admin",
      authenticated: true,
    };

    // Store session
    const sessions = col("sessions");
    await sessions.insertOne({ token, user, created_at: new Date() });

    res.json({ token, user });
  } catch (err) {
    logger.error({ err }, "Login error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/auth/logout", async (req, res) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (token) {
    await col("sessions").deleteOne({ token });
  }
  res.json({ message: "Logged out" });
});

router.get("/auth/me", async (req, res) => {
  const token = req.headers.authorization?.replace("Bearer ", "");

  if (token) {
    const session = await col("sessions").findOne({ token } as Record<string, unknown>) as { user?: unknown } | null;
    if (session?.user) return res.json(session.user);
  }

  // Demo mode: return default admin user when no token
  res.json({
    id: "user_wajahat883",
    github_login: "Wajahat883",
    role: "admin",
    authenticated: true,
  });
});

export default router;
