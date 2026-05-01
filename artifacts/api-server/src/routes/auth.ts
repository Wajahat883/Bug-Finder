import { Router } from "express";
import bcrypt from "bcrypt";
import { pool } from "../lib/pgDb";
import { logger } from "../lib/logger";
import { auditFromReq } from "../lib/audit";

const router = Router();

interface SessionData {
  userId?: string;
  username?: string;
  role?: string;
}

function getSession(req: Parameters<typeof auditFromReq>[0]): SessionData {
  return req.session as SessionData;
}

function generateId(): string {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

router.post("/auth/register", async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body as {
      firstName?: string; lastName?: string; email?: string; password?: string;
    };
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ error: "First name, last name, email, and password are required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const baseUsername = `${firstName.trim().toLowerCase()}_${lastName.trim().toLowerCase()}`.replace(/[^a-z0-9_]/g, "");
    const existing = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (existing.rows.length) {
      return res.status(409).json({ error: "An account with this email already exists" });
    }

    let username = baseUsername;
    const taken = await pool.query("SELECT id FROM users WHERE username=$1", [username]);
    if (taken.rows.length) {
      username = `${baseUsername}_${Math.floor(Math.random() * 9000) + 1000}`;
    }

    const hashed = await bcrypt.hash(password, 10);
    const id = generateId();
    await pool.query(
      "INSERT INTO users(id, username, email, password, role, first_name, last_name) VALUES($1,$2,$3,$4,$5,$6,$7)",
      [id, username, email, hashed, "analyst", firstName.trim(), lastName.trim()]
    );

    const session = getSession(req);
    session.userId = id;
    session.username = username;
    session.role = "analyst";

    await auditFromReq(req, "user.register", "users", id, { username, email });

    res.status(201).json({ id, username, email, role: "analyst" });
  } catch (err) {
    logger.error({ err }, "Register error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body as { email?: string; password?: string };
    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required" });
    }

    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    const user = result.rows[0] as { id: string; username: string; email: string; password: string; role: string } | undefined;

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const session = getSession(req);
    session.userId = user.id;
    session.username = user.username;
    session.role = user.role;

    await auditFromReq(req, "user.login", "users", user.id);

    res.json({ id: user.id, username: user.username, email: user.email, role: user.role });
  } catch (err) {
    logger.error({ err }, "Login error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/auth/logout", async (req, res) => {
  const session = getSession(req);
  if (session.userId) {
    await auditFromReq(req, "user.logout", "users", session.userId);
  }
  req.session.destroy(() => {
    res.clearCookie("bbp.sid");
    res.json({ ok: true });
  });
});

router.get("/auth/me", (req, res) => {
  const session = getSession(req);
  if (!session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  res.json({ id: session.userId, username: session.username, role: session.role });
});

router.post("/auth/demo", async (req, res) => {
  try {
    const existing = await pool.query("SELECT * FROM users WHERE email='demo@bugfinder.io'");
    let user = existing.rows[0] as { id: string; username: string; email: string; role: string } | undefined;

    if (!user) {
      const hashed = await bcrypt.hash("demo1234", 10);
      const id = generateId();
      await pool.query(
        "INSERT INTO users(id, username, email, password, role) VALUES($1,$2,$3,$4,$5)",
        [id, "demo_admin", "demo@bugfinder.io", hashed, "admin"]
      );
      user = { id, username: "demo_admin", email: "demo@bugfinder.io", role: "admin" };
    }

    const session = getSession(req);
    session.userId = user.id;
    session.username = user.username;
    session.role = user.role;

    res.json({ id: user.id, username: user.username, email: user.email, role: user.role });
  } catch (err) {
    logger.error({ err }, "Demo login error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
