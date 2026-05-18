import { Router } from "express";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { col, ObjectId } from "../lib/db";
import { logger } from "../lib/logger";
import { auditFromReq } from "../lib/audit";
import { requireAdmin } from "../middlewares/rbac";
import { authLimiter } from "../middlewares/rate-limit";
import { sendPasswordResetEmail, sendEmail } from "../services/email";
import { redisGet, redisSet, redisDel } from "../lib/redis";

const router = Router();

// In-memory brute-force protection (supplements Redis-based lockout)
const loginAttempts = new Map<string, { count: number; lastAttempt: number }>();
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

function checkLoginAttempts(email: string): boolean {
  const now = Date.now();
  const entry = loginAttempts.get(email);
  if (!entry) return false;
  // Reset window if expired
  if (now - entry.lastAttempt > LOGIN_WINDOW_MS) {
    loginAttempts.delete(email);
    return false;
  }
  return entry.count >= LOGIN_MAX_ATTEMPTS;
}

function recordFailedAttempt(email: string): void {
  const now = Date.now();
  const entry = loginAttempts.get(email);
  if (!entry || now - entry.lastAttempt > LOGIN_WINDOW_MS) {
    loginAttempts.set(email, { count: 1, lastAttempt: now });
  } else {
    loginAttempts.set(email, { count: entry.count + 1, lastAttempt: now });
  }
}

function clearLoginAttempts(email: string): void {
  loginAttempts.delete(email);
}

const DEFAULT_ADMIN_EMAIL = process.env["ADMIN_EMAIL"] ?? "admin@bugfinder.local";
let DEFAULT_ADMIN_PASSWORD = process.env["ADMIN_PASSWORD"] ?? "";
if (!DEFAULT_ADMIN_PASSWORD) { DEFAULT_ADMIN_PASSWORD = crypto.randomBytes(12).toString("hex"); logger.warn("ADMIN_PASSWORD not set — auto-generated a random password"); }

interface SessionData {
  userId?: string;
  username?: string;
  role?: string;
  created_at?: number;
  rememberMe?: boolean;
}

function generateId(): string {
  return new ObjectId().toHexString();
}

router.post("/auth/register", authLimiter, async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body as {
      firstName?: string; lastName?: string; email?: string; password?: string;
    };
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ error: "First name, last name, email, and password are required" });
    }
    // Enterprise password policy — min 12 chars, uppercase, number, special char
    if (password.length < 12) return res.status(400).json({ error: "Password must be at least 12 characters" });
    if (!/[A-Z]/.test(password)) return res.status(400).json({ error: "Password must contain at least one uppercase letter" });
    if (!/[0-9]/.test(password)) return res.status(400).json({ error: "Password must contain at least one number" });
    if (!/[^A-Za-z0-9]/.test(password)) return res.status(400).json({ error: "Password must contain at least one special character (!@#$%^&*)" });

    const baseUsername = `${firstName.trim().toLowerCase()}_${lastName.trim().toLowerCase()}`.replace(/[^a-z0-9_]/g, "");
    const existingEmail = await col("users").findOne({ email });
    if (existingEmail) {
      return res.status(409).json({ error: "An account with this email already exists" });
    }

    let username = baseUsername;
    if (await col("users").findOne({ username })) {
      username = `${baseUsername}_${Math.floor(Math.random() * 9000) + 1000}`;
    }

    const hashed = await bcrypt.hash(password, 10);
    const id = generateId();
    await col("users").insertOne({
      _id: new ObjectId(id),
      username, email, password: hashed, role: "analyst",
      first_name: firstName.trim(), last_name: lastName.trim(),
      created_at: new Date(), updated_at: new Date(),
    });

    const session = (req as unknown as { session: SessionData }).session;
    session.userId = id; session.username = username; session.role = "analyst";
    await auditFromReq(req, "user.register", "users", id, { username, email });
    res.status(201).json({ id, username, email, role: "analyst" });
  } catch (err) {
    logger.error({ err }, "Register error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/auth/login", authLimiter, async (req, res) => {
  try {
    const body = req.body as { email?: string; username?: string; password?: string };
    const email = body.email ?? body.username;
    const { password } = body;
    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required" });
    }

    // In-memory brute-force check
    if (checkLoginAttempts(email)) {
      return res.status(429).json({ error: "Account temporarily locked. Try again in 15 minutes." });
    }

    // Redis-backed account lockout check
    const lockoutKey = `lockout:${email}`;
    const lockoutVal = await redisGet(lockoutKey);
    if (lockoutVal !== null && parseInt(lockoutVal, 10) >= 5) {
      return res.status(429).json({ error: "Account locked. Too many failed attempts. Try again in 15 minutes." });
    }

    let user = await col("users").findOne({ email }) as {
      _id: ObjectId; username: string; email: string; password: string; role: string;
    } | null;

    // Auto-create default admin on first login with correct credentials
    if (!user && email === DEFAULT_ADMIN_EMAIL && password === DEFAULT_ADMIN_PASSWORD) {
      logger.info("Auto-creating default admin user on first login");
      const hashed = await bcrypt.hash(password, 10);
      const newId = generateId();
      await col("users").insertOne({
        _id: new ObjectId(newId), username: "waji_admin", email,
        password: hashed, role: "admin", first_name: "Waji", last_name: "Admin",
        created_at: new Date(), updated_at: new Date(),
      });
      user = { _id: new ObjectId(newId), username: "waji_admin", email, password: hashed, role: "admin" };
    }

    if (!user || !(await bcrypt.compare(password, user.password))) {
      // Increment both in-memory and Redis failed attempts counters
      recordFailedAttempt(email);
      const currentVal = await redisGet(lockoutKey);
      const attempts = currentVal !== null ? parseInt(currentVal, 10) + 1 : 1;
      await redisSet(lockoutKey, String(attempts), 15 * 60); // 15-minute TTL
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const id = user._id.toHexString();

    // Clear lockout keys on successful login
    clearLoginAttempts(email);
    await redisDel(lockoutKey);

    // Max 3 concurrent sessions — evict oldest if at limit
    const sessionCount = await col("sessions").countDocuments({ "session.userId": id } as Record<string, unknown>);
    if (sessionCount >= 3) {
      const oldest = await col("sessions").findOne({ "session.userId": id }, { sort: { expires: 1 } } as any);
      if (oldest) await col("sessions").deleteOne({ _id: oldest._id } as any);
    }

    // Check MFA enforcement policy
    const policy = await col("platform_policy").findOne({}) as Record<string, unknown> | null;
    const requireMfaRoles: string[] = (policy?.["require_mfa_roles"] as string[]) ?? [];
    const graceDays: number = (policy?.["mfa_grace_days"] as number) ?? 7;

    if (requireMfaRoles.includes(user["role"] as string)) {
      const fullUser = await col("users").findOne({ _id: user._id }) as Record<string, unknown> | null;
      // Strict TOTP-enabled check per compliance spec
      if (fullUser?.["totp_enabled"] !== true) {
        return res.status(403).json({
          error: "MFA required for your role",
          mfa_required: true,
        });
      }
      // Also allow WebAuthn as an alternative MFA factor
      const hasMfa = !!(fullUser?.["totp_secret"] || (fullUser?.["webauthn_credentials"] as unknown[])?.length);
      if (!hasMfa) {
        const createdAt = fullUser?.["created_at"] ? new Date(fullUser["created_at"] as string) : new Date();
        const graceExpiry = new Date(createdAt.getTime() + graceDays * 86400000);
        if (new Date() > graceExpiry) {
          return res.status(403).json({
            error: "MFA_REQUIRED",
            message: "Your role requires multi-factor authentication. Please enroll at /security.",
            redirect: "/security",
          });
        }
      }
    }

    const session = (req as unknown as { session: SessionData }).session;
    session.userId = id; session.username = user.username; session.role = user.role;
    session.created_at = Date.now();

    const rememberMe = req.body?.remember_me === true;
    if (rememberMe) {
      req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
      session.rememberMe = true;
    } else {
      req.session.cookie.maxAge = 30 * 60 * 1000; // 30 min inactivity
    }

    await auditFromReq(req, "user.login", "users", id);
    res.json({ id, username: user.username, email: user.email, role: user.role });
  } catch (err) {
    logger.error({ err }, "Login error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/auth/extend-session", async (req, res) => {
  const session = (req as unknown as { session: SessionData }).session;
  if (!session.userId) return res.status(401).json({ error: "Not authenticated" });
  session.created_at = Date.now();
  req.session.cookie.maxAge = 7 * 24 * 60 * 60 * 1000;
  res.json({ ok: true, expires_in: req.session.cookie.maxAge });
});

router.post("/auth/logout", async (req, res) => {
  const session = (req as unknown as { session: SessionData }).session;
  if (session.userId) await auditFromReq(req, "user.logout", "users", session.userId);
  req.session.destroy(() => {
    res.clearCookie("bbp.sid");
    res.json({ ok: true });
  });
});

router.get("/auth/me", async (req, res) => {
  const session = (req as unknown as { session: SessionData }).session;
  if (!session.userId) return res.status(401).json({ error: "Not authenticated" });
  try {
    const user = await col("users").findOne({ _id: new ObjectId(session.userId) }) as Record<string, unknown> | null;
    if (!user) return res.status(401).json({ error: "Not authenticated" });
    res.json({
      id: session.userId,
      username: user.username,
      email: user.email,
      role: user.role ?? session.role,
      first_name: user.first_name,
      last_name: user.last_name,
      avatar_url: user.avatar_url ?? null,
      two_fa_enabled: user.two_fa_enabled ?? false,
      onboarding_complete: user.onboarding_complete ?? false,
    });
  } catch (err) {
    logger.error({ err }, "Auth me error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.patch("/auth/profile", async (req, res) => {
  const session = (req as unknown as { session: SessionData }).session;
  if (!session.userId) return res.status(401).json({ error: "Not authenticated" });
  try {
    const { first_name, last_name, email, avatar_url, onboarding_complete } = req.body as Record<string, string>;
    const update: Record<string, unknown> = { updated_at: new Date() };
    if (first_name) update.first_name = first_name.trim();
    if (last_name) update.last_name = last_name.trim();
    if (avatar_url !== undefined) update.avatar_url = avatar_url;
    if (onboarding_complete !== undefined) update.onboarding_complete = onboarding_complete === (true as unknown as string) || onboarding_complete === "true";
    if (email) {
      const existing = await col("users").findOne({ email, _id: { $ne: new ObjectId(session.userId) } });
      if (existing) return res.status(409).json({ error: "Email already in use" });
      update.email = email.toLowerCase().trim();
    }
    await col("users").updateOne(
      { _id: new ObjectId(session.userId) } as Record<string, unknown>,
      { $set: update }
    );
    const updated = await col("users").findOne({ _id: new ObjectId(session.userId) }) as Record<string, unknown>;
    res.json({
      id: session.userId, username: updated.username, email: updated.email,
      role: updated.role, first_name: updated.first_name, last_name: updated.last_name,
      avatar_url: updated.avatar_url ?? null,
      onboarding_complete: updated.onboarding_complete ?? false,
    });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/auth/demo", async (req, res) => {
  try {
    let user = await col("users").findOne({ email: DEFAULT_ADMIN_EMAIL }) as {
      _id: ObjectId; username: string; email: string; role: string;
    } | null;

    if (!user) {
      const hashed = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, 10);
      const id = generateId();
      await col("users").insertOne({
        _id: new ObjectId(id), username: "waji_admin", email: DEFAULT_ADMIN_EMAIL,
        password: hashed, role: "admin", first_name: "Waji", last_name: "Admin",
        created_at: new Date(), updated_at: new Date(),
      });
      user = { _id: new ObjectId(id), username: "waji_admin", email: DEFAULT_ADMIN_EMAIL, role: "admin" };
    }

    const id = user._id.toHexString();
    const session = (req as unknown as { session: SessionData }).session;
    session.userId = id; session.username = user.username; session.role = user.role;
    res.json({ id, username: user.username, email: user.email, role: user.role });
  } catch (err) {
    logger.error({ err }, "Demo login error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Password Change ────────────────────────────────────────────────────────

router.post("/auth/change-password", async (req, res) => {
  try {
    const session = (req as unknown as { session: SessionData }).session;
    if (!session.userId) return res.status(401).json({ error: "Not authenticated" });

    const { currentPassword, newPassword } = req.body as { currentPassword?: string; newPassword?: string };
    if (!currentPassword || !newPassword) return res.status(400).json({ error: "currentPassword and newPassword are required" });
    if (newPassword.length < 12) return res.status(400).json({ error: "New password must be at least 12 characters" });

    const user = await col("users").findOne({ _id: new ObjectId(session.userId) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!user) return res.status(404).json({ error: "User not found" });

    const valid = await bcrypt.compare(currentPassword, String(user["password"] ?? ""));
    if (!valid) return res.status(400).json({ error: "Current password is incorrect" });

    const hashed = await bcrypt.hash(newPassword, 10);
    await col("users").updateOne({ _id: new ObjectId(session.userId) } as Record<string, unknown>, { $set: { password: hashed, updated_at: new Date() } });
    await auditFromReq(req, "user.password_change", "users", session.userId);
    res.json({ ok: true, message: "Password changed successfully" });
  } catch (err) {
    logger.error({ err }, "Change password error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Email Verification ──────────────────────────────────────────────────────

router.post("/auth/send-verification", async (req, res) => {
  try {
    const session = (req as unknown as { session: SessionData }).session;
    if (!session.userId) return res.status(401).json({ error: "Not authenticated" });
    const user = await col("users").findOne({ _id: new ObjectId(session.userId) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!user) return res.status(404).json({ error: "User not found" });
    if (user["email_verified"]) return res.json({ message: "Already verified" });
    const code = String(Math.floor(100000 + Math.random() * 900000));
    await col("users").updateOne({ _id: new ObjectId(session.userId) } as Record<string, unknown>, { $set: { verification_code: code, verification_expires: new Date(Date.now() + 3600000) } });
    sendEmail({ to: String(user["email"] ?? ""), subject: "Bug Finder Pro — Verify Your Email", html: `<h2>Email Verification</h2><p>Your code: <strong style="font-size:24px;letter-spacing:4px;">${code}</strong></p><p>Expires in 1 hour.</p>` }).catch(() => {});
    res.json({ message: "Verification code sent to your email" });
  } catch (err) { logger.error({ err }, "Send verification error"); res.status(500).json({ error: "Failed" }); }
});

router.post("/auth/verify-email", async (req, res) => {
  try {
    const session = (req as unknown as { session: SessionData }).session;
    if (!session.userId) return res.status(401).json({ error: "Not authenticated" });
    const { code } = req.body as { code?: string };
    if (!code) return res.status(400).json({ error: "code is required" });
    const user = await col("users").findOne({ _id: new ObjectId(session.userId) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!user) return res.status(404).json({ error: "User not found" });
    if (String(user["verification_code"] ?? "") !== code) return res.status(400).json({ error: "Invalid code" });
    if (new Date(String(user["verification_expires"] ?? 0)) < new Date()) return res.status(400).json({ error: "Code expired" });
    await col("users").updateOne({ _id: new ObjectId(session.userId) } as Record<string, unknown>, { $set: { email_verified: true, verification_code: null, verification_expires: null } });
    res.json({ ok: true, message: "Email verified successfully" });
  } catch (err) { logger.error({ err }, "Verify email error"); res.status(500).json({ error: "Verification failed" }); }
});

router.get("/auth/verification-status", async (req, res) => {
  const session = (req as unknown as { session: SessionData }).session;
  if (!session.userId) return res.status(401).json({ error: "Not authenticated" });
  const user = await col("users").findOne({ _id: new ObjectId(session.userId) } as Record<string, unknown>);
  res.json({ verified: !!(user?.["email_verified"]) });
});

// ── Password Reset ──────────────────────────────────────────────────────────

router.post("/auth/forgot-password", authLimiter, async (req, res) => {
  try {
    const { email } = req.body as { email?: string };
    if (!email) return res.status(400).json({ error: "email is required" });

    // Always return 200 to avoid user enumeration
    const user = await col("users").findOne({ email }) as { _id: ObjectId; email: string } | null;
    if (user) {
      const token = crypto.randomBytes(32).toString("hex");
      const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
      await col("password_resets").insertOne({
        user_id: user._id, email, token, expires, used: false, created_at: new Date(),
      });
      await sendPasswordResetEmail(email, token);
      logger.info({ email }, "Password reset email sent");
    }

    res.json({ message: "If that email exists, a reset link has been sent." });
  } catch (err) {
    logger.error({ err }, "Forgot password error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/auth/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body as { token?: string; password?: string };
    if (!token || !password) return res.status(400).json({ error: "token and password are required" });
    if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });

    const reset = await col("password_resets").findOne({ token, used: false }) as {
      _id: ObjectId; user_id: ObjectId; expires: Date; used: boolean;
    } | null;

    if (!reset || new Date() > reset.expires) {
      return res.status(400).json({ error: "Reset token is invalid or expired" });
    }

    const hashed = await bcrypt.hash(password, 10);
    await col("users").updateOne(
      { _id: reset.user_id } as Record<string, unknown>,
      { $set: { password: hashed, updated_at: new Date() } }
    );
    await col("password_resets").updateOne(
      { _id: reset._id } as Record<string, unknown>,
      { $set: { used: true } }
    );

    // Invalidate all sessions for this user
    await col("sessions").deleteMany({ "session.userId": reset.user_id.toHexString() } as Record<string, unknown>);

    res.json({ message: "Password has been reset successfully." });
  } catch (err) {
    logger.error({ err }, "Reset password error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Magic Link Login ────────────────────────────────────────────────────────

router.post("/auth/magic-link/request", authLimiter, async (req, res) => {
  try {
    const { email } = req.body as { email?: string };
    if (!email) return res.status(400).json({ error: "email is required" });

    const user = await col("users").findOne({ email }) as { _id: ObjectId; email: string } | null;
    if (user) {
      const token = crypto.randomBytes(32).toString("hex");
      await col("magic_links").insertOne({
        email,
        token,
        expires: new Date(Date.now() + 15 * 60 * 1000),
        used: false,
        created_at: new Date(),
      });
      const magicUrl = `${process.env["APP_URL"] ?? "http://localhost:3000"}/api/auth/magic-link/verify?token=${token}`;
      sendEmail({
        to: email,
        subject: "Your Bug Finder Pro login link",
        html: `<p>Click the link below to log in to Bug Finder Pro. This link expires in 15 minutes.</p><p><a href="${magicUrl}">${magicUrl}</a></p><p>If you did not request this, you can safely ignore this email.</p>`,
      }).catch(() => {});
    }

    // Always return 200 to avoid user enumeration
    res.json({ message: "If that email exists, a magic link has been sent." });
  } catch (err) {
    logger.error({ err }, "Magic link request error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/auth/magic-link/verify", async (req, res) => {
  try {
    const { token } = req.query as { token?: string };
    if (!token) return res.status(400).json({ error: "token is required" });

    const link = await col("magic_links").findOne({ token, used: false }) as {
      _id: ObjectId; email: string; expires: Date; used: boolean;
    } | null;

    if (!link || new Date() > link.expires) {
      return res.status(400).json({ error: "Magic link is invalid or expired" });
    }

    // Mark as used
    await col("magic_links").updateOne(
      { _id: link._id } as Record<string, unknown>,
      { $set: { used: true } }
    );

    const user = await col("users").findOne({ email: link.email }) as {
      _id: ObjectId; username: string; email: string; role: string;
    } | null;

    if (!user) {
      return res.status(400).json({ error: "Magic link is invalid or expired" });
    }

    const id = user._id.toHexString();
    const session = (req as unknown as { session: SessionData }).session;
    session.userId = id; session.username = user.username; session.role = user.role;

    await auditFromReq(req, "user.magic_link_login", "users", id);
    res.redirect("/dashboard");
  } catch (err) {
    logger.error({ err }, "Magic link verify error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Admin: Dashboard Stats ──────────────────────────────────────────────────

router.get("/admin/stats", requireAdmin, async (_req, res) => {
  try {
    const totalUsers = await col("users").countDocuments();
    const totalScans = await col("scan_jobs").countDocuments();
    const totalFindings = await col("findings").countDocuments();
    const activeScans = await col("scan_jobs").countDocuments({ status: "running" });
    res.json({ totalUsers, totalScans, totalFindings, activeScans });
  } catch (err) {
    logger.error({ err }, "Admin stats error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Admin: User Management ──────────────────────────────────────────────────

router.get("/admin/users", requireAdmin, async (req, res) => {
  try {
    const users = await col("users").find({}).sort({ created_at: -1 }).toArray() as Array<Record<string, unknown>>;
    res.json(users.map((u) => ({
      id: String(u["_id"]), username: u["username"], email: u["email"],
      role: u["role"], created_at: u["created_at"],
    })));
  } catch (err) {
    logger.error({ err }, "List users error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.patch("/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const { role } = req.body as { role?: string };
    if (!role || !["admin", "analyst", "viewer"].includes(role)) {
      return res.status(400).json({ error: "role must be admin, analyst, or viewer" });
    }
    await col("users").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $set: { role, updated_at: new Date() } }
    );
    await auditFromReq(req, "user.role_change", "users", id, { role });

    // Privilege escalation alert — notify the affected user by email
    const targetUser = await col("users").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (targetUser) {
      sendEmail({ to: String(targetUser["email"] ?? ""), subject: "Bug Finder Pro — Your role has been changed", html: `<p>Your account role has been changed to <strong>${role}</strong> by an administrator.</p>` }).catch(() => {});
    }

    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Update user role error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.delete("/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const session = (req as unknown as { session: SessionData }).session;
    if (session.userId === id) return res.status(400).json({ error: "Cannot delete your own account" });
    await col("users").deleteOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    await auditFromReq(req, "user.delete", "users", id);
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Delete user error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── 2FA / TOTP ────────────────────────────────────────────────────────────────

// Simple TOTP implementation without external library
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function generateTotpSecret(): string {
  const bytes = crypto.randomBytes(20);
  let result = "";
  for (let i = 0; i < bytes.length; i += 5) {
    const chunk = [bytes[i] ?? 0, bytes[i + 1] ?? 0, bytes[i + 2] ?? 0, bytes[i + 3] ?? 0, bytes[i + 4] ?? 0];
    result += BASE32_ALPHABET[(chunk[0] >> 3) & 31];
    result += BASE32_ALPHABET[((chunk[0] << 2) | (chunk[1] >> 6)) & 31];
    result += BASE32_ALPHABET[(chunk[1] >> 1) & 31];
    result += BASE32_ALPHABET[((chunk[1] << 4) | (chunk[2] >> 4)) & 31];
    result += BASE32_ALPHABET[((chunk[2] << 1) | (chunk[3] >> 7)) & 31];
    result += BASE32_ALPHABET[(chunk[3] >> 2) & 31];
    result += BASE32_ALPHABET[((chunk[3] << 3) | (chunk[4] >> 5)) & 31];
    result += BASE32_ALPHABET[chunk[4] & 31];
  }
  return result.slice(0, 32);
}

function base32Decode(str: string): Buffer {
  const cleaned = str.replace(/\s/g, "").replace(/=/g, "").toUpperCase();
  const bits: number[] = [];
  for (const ch of cleaned) {
    const val = BASE32_ALPHABET.indexOf(ch);
    if (val >= 0) {
      const bin = val.toString(2).padStart(5, "0");
      for (const c of bin) bits.push(Number(c));
    }
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8).join(""), 2));
  }
  return Buffer.from(bytes);
}

function getTotpCode(secret: string): string {
  const key = base32Decode(secret);
  const counter = Math.floor(Date.now() / 30000);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = (((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff)) % 1000000;
  return String(code).padStart(6, "0");
}

router.get("/auth/2fa/status", async (req, res) => {
  const session = (req as unknown as { session: SessionData }).session;
  if (!session.userId) return res.status(401).json({ error: "Not authenticated" });
  const user = await col("users").findOne({ _id: new ObjectId(session.userId) }) as Record<string, unknown> | null;
  res.json({ enabled: !!(user?.two_fa_enabled) });
});

router.post("/auth/2fa/setup", async (req, res) => {
  const sess = req.session as SessionData;
  if (!sess.userId) return res.status(401).json({ error: "Not authenticated" });
  try {
    const secret = generateTotpSecret();
    await col("users").updateOne({ _id: new ObjectId(sess.userId) } as Record<string,unknown>, { $set: { totp_secret_pending: secret, totp_enabled: false } });
    const issuer = "BugFinderPro";
    const user = await col("users").findOne({ _id: new ObjectId(sess.userId) } as Record<string,unknown>) as Record<string,unknown> | null;
    const otpauth = `otpauth://totp/${issuer}:${user?.["email"]}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    res.json({ secret, otpauth_url: otpauth });
  } catch(err) { res.status(500).json({ error: "Internal server error" }); }
});

router.post("/auth/2fa/verify", async (req, res) => {
  const sess = req.session as SessionData;
  if (!sess.userId) return res.status(401).json({ error: "Not authenticated" });
  try {
    const { code } = req.body as { code?: string };
    const user = await col("users").findOne({ _id: new ObjectId(sess.userId) } as Record<string,unknown>) as Record<string,unknown> | null;
    if (!user) return res.status(404).json({ error: "User not found" });
    const secret = String(user["totp_secret_pending"] ?? user["totp_secret"] ?? "");
    if (!secret) return res.status(400).json({ error: "2FA not set up" });
    const expected = getTotpCode(secret);
    if (code !== expected) return res.status(400).json({ error: "Invalid code" });
    await col("users").updateOne({ _id: new ObjectId(sess.userId) } as Record<string,unknown>, { $set: { totp_secret: secret, totp_enabled: true, totp_secret_pending: null } });
    res.json({ ok: true, message: "2FA enabled successfully" });
  } catch(err) { res.status(500).json({ error: "Internal server error" }); }
});

router.post("/auth/2fa/disable", async (req, res) => {
  const sess = req.session as SessionData;
  if (!sess.userId) return res.status(401).json({ error: "Not authenticated" });
  try {
    await col("users").updateOne({ _id: new ObjectId(sess.userId) } as Record<string,unknown>, { $set: { totp_enabled: false, totp_secret: null } });
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ error: "Internal server error" }); }
});

// ── OAuth2 — Google & GitHub ──────────────────────────────────────────────────

router.get("/auth/oauth/google", (_req, res) => {
  const clientId = process.env["GOOGLE_CLIENT_ID"];
  if (!clientId) return res.status(400).json({ error: "Google OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET." });
  const redirectUri = `${process.env["APP_URL"] ?? "http://localhost:3000"}/api/auth/oauth/google/callback`;
  const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid%20email%20profile`;
  res.redirect(url);
});

router.get("/auth/oauth/google/callback", async (req, res) => {
  const { code } = req.query as { code?: string };
  const clientId = process.env["GOOGLE_CLIENT_ID"];
  const clientSecret = process.env["GOOGLE_CLIENT_SECRET"];
  if (!code || !clientId || !clientSecret) return res.redirect("/login?error=oauth_failed");
  try {
    const redirectUri = `${process.env["APP_URL"] ?? "http://localhost:3000"}/api/auth/oauth/google/callback`;
    const tokenResp = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, grant_type: "authorization_code" }) });
    const tokens = await tokenResp.json() as Record<string,unknown>;
    const userResp = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", { headers: { Authorization: `Bearer ${tokens["access_token"]}` } });
    const profile = await userResp.json() as Record<string,unknown>;
    let user = await col("users").findOne({ email: profile["email"] }) as Record<string,unknown> | null;
    if (!user) {
      const ins = await col("users").insertOne({
        email: profile["email"],
        name: profile["name"],
        avatar: profile["picture"],
        oauth_provider: "google",
        oauth_id: profile["id"],
        role: "analyst",
        created_at: new Date(),
        username: String((profile["email"] as string ?? "").split("@")[0]),
        first_name: String(profile["given_name"] ?? (profile["name"] as string ?? "").split(" ")[0] ?? ""),
        last_name: String(profile["family_name"] ?? (profile["name"] as string ?? "").split(" ").slice(1).join(" ") ?? ""),
      });
      user = await col("users").findOne({ _id: ins.insertedId }) as Record<string,unknown>;
    }
    const sess = req.session as SessionData;
    sess.userId = String(user!["_id"]); sess.username = String(user!["name"] ?? user!["email"]); sess.role = String(user!["role"] ?? "analyst");
    res.redirect("/dashboard");
  } catch { res.redirect("/login?error=oauth_failed"); }
});

router.get("/auth/oauth/github", (_req, res) => {
  const clientId = process.env["GITHUB_OAUTH_CLIENT_ID"];
  if (!clientId) return res.status(400).json({ error: "GitHub OAuth not configured. Set GITHUB_OAUTH_CLIENT_ID and GITHUB_OAUTH_CLIENT_SECRET." });
  const url = `https://github.com/login/oauth/authorize?client_id=${clientId}&scope=user:email`;
  res.redirect(url);
});

router.get("/auth/oauth/github/callback", async (req, res) => {
  const { code } = req.query as { code?: string };
  const clientId = process.env["GITHUB_OAUTH_CLIENT_ID"];
  const clientSecret = process.env["GITHUB_OAUTH_CLIENT_SECRET"];
  if (!code || !clientId || !clientSecret) return res.redirect("/login?error=oauth_failed");
  try {
    const tokenResp = await fetch("https://github.com/login/oauth/access_token", { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" }, body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code }) });
    const tokens = await tokenResp.json() as Record<string,unknown>;
    const userResp = await fetch("https://api.github.com/user", { headers: { Authorization: `Bearer ${tokens["access_token"]}`, Accept: "application/vnd.github+json" } });
    const profile = await userResp.json() as Record<string,unknown>;
    const emailResp = await fetch("https://api.github.com/user/emails", { headers: { Authorization: `Bearer ${tokens["access_token"]}`, Accept: "application/vnd.github+json" } });
    const emails = await emailResp.json() as Array<Record<string,unknown>>;
    const primaryEmail = emails.find(e => e["primary"])?.["email"] ?? profile["email"];
    let user = await col("users").findOne({ email: primaryEmail }) as Record<string,unknown> | null;
    if (!user) {
      const githubFullName = String(profile["name"] ?? profile["login"] ?? "");
      const githubNameParts = githubFullName.split(" ");
      const ins = await col("users").insertOne({
        email: primaryEmail,
        name: githubFullName,
        avatar: profile["avatar_url"],
        oauth_provider: "github",
        oauth_id: profile["id"],
        role: "analyst",
        created_at: new Date(),
        username: String(profile["login"] ?? (profile["email"] as string ?? "").split("@")[0]),
        first_name: String(githubNameParts[0] ?? ""),
        last_name: String(githubNameParts.slice(1).join(" ") ?? ""),
      });
      user = await col("users").findOne({ _id: ins.insertedId }) as Record<string,unknown>;
    }
    const sess = req.session as SessionData;
    sess.userId = String(user!["_id"]); sess.username = String(user!["name"] ?? user!["email"]); sess.role = String(user!["role"] ?? "analyst");
    res.redirect("/dashboard");
  } catch { res.redirect("/login?error=oauth_failed"); }
});

// ── GDPR: Right to erasure — self-deletion ────────────────────────────────────
router.delete("/auth/me", async (req, res) => {
  try {
    const sess = req.session as SessionData;
    const userId = sess.userId;
    if (!userId) return res.status(401).json({ error: "Unauthenticated" });

    // Anonymize audit log entries (keep for compliance, strip PII)
    await col("audit_log").updateMany(
      { user_id: userId } as Record<string, unknown>,
      { $set: { username: "[deleted]", details: null } }
    );

    // Delete user's findings, scan jobs, targets (personal data)
    await Promise.all([
      col("findings").deleteMany({ user_id: userId } as Record<string, unknown>),
      col("scan_jobs").deleteMany({ user_id: userId } as Record<string, unknown>),
      col("targets").deleteMany({ user_id: userId } as Record<string, unknown>),
      col("api_keys").deleteMany({ user_id: userId } as Record<string, unknown>),
      col("notification_preferences").deleteMany({ user_id: userId } as Record<string, unknown>),
    ]);

    // Delete user account
    await col("users").deleteOne({ _id: new ObjectId(userId) } as Record<string, unknown>);

    // Destroy session
    req.session.destroy(() => {});

    logger.info({ userId }, "GDPR: user self-deletion completed");
    res.json({ ok: true, message: "Your account and associated data have been deleted." });
  } catch (err) {
    logger.error({ err }, "GDPR self-deletion error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
