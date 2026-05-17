import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth, requireAdmin } from "../middlewares/rbac";

const router = Router();

// Extended role system:
// admin    — full access
// manager  — can see all projects, assign team members, manage scope
// analyst  — can see assigned targets only
// viewer   — read-only on assigned targets
const ROLES = ["admin", "manager", "analyst", "viewer"];

function getRolePriority(role: string): number {
  return ROLES.indexOf(role);
}

async function canAccessTarget(userId: string, userRole: string, targetUrl: string): Promise<boolean> {
  if (userRole === "admin") return true;

  const assignment = await col("target_assignments").findOne({
    user_id: userId,
    target_url: targetUrl,
  } as Record<string, unknown>);

  return !!assignment;
}

// POST /projects — Create a project
router.post("/projects", requireAdmin, async (req, res) => {
  try {
    const { name, description, targets } = req.body as {
      name?: string; description?: string; targets?: string[];
    };

    if (!name) return res.status(400).json({ error: "name is required" });

    const insert = await col("projects").insertOne({
      name,
      description: description ?? "",
      targets: targets ?? [],
      created_by: (req as unknown as { session: { userId: string } }).session.userId,
      created_at: new Date(),
      updated_at: new Date(),
    });

    res.status(201).json({ id: String(insert.insertedId), name, description, targets });
  } catch (err) {
    logger.error({ err }, "Create project error");
    res.status(500).json({ error: "Failed to create project" });
  }
});

// GET /projects — List projects (admin: all, others: assigned only)
router.get("/projects", requireAuth, async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId: string; role: string } }).session;
    const isAdmin = session.role === "admin";

    let projects;
    if (isAdmin) {
      projects = await col("projects").find({}).toArray() as Array<Record<string, unknown>>;
    } else {
      const assignments = await col("target_assignments")
        .find({ user_id: session.userId })
        .toArray() as Array<Record<string, unknown>>;

      const targetUrls = [...new Set(assignments.map(a => String(a["target_url"])))];

      projects = await col("projects")
        .find({ targets: { $in: targetUrls } })
        .toArray() as Array<Record<string, unknown>>;
    }

    res.json(projects.map(p => ({
      id: String(p["_id"]),
      name: p["name"],
      description: p["description"],
      targetCount: (p["targets"] as string[])?.length ?? 0,
      created_at: p["created_at"],
    })));
  } catch (err) {
    logger.error({ err }, "List projects error");
    res.status(500).json({ error: "Failed to list projects" });
  }
});

// POST /projects/:id/assign — Assign user to project with role
router.post("/projects/:id/assign", requireAdmin, async (req, res) => {
  try {
    const { userId, targetUrl, role = "analyst" } = req.body as {
      userId?: string; targetUrl?: string; role?: string;
    };

    if (!userId || !targetUrl) {
      return res.status(400).json({ error: "userId and targetUrl are required" });
    }

    if (!ROLES.includes(role)) {
      return res.status(400).json({ error: `Role must be one of: ${ROLES.join(", ")}` });
    }

    const existing = await col("target_assignments").findOne({
      user_id: userId,
      target_url: targetUrl,
    } as Record<string, unknown>);

    if (existing) {
      await col("target_assignments").updateOne(
        { _id: existing["_id"] } as Record<string, unknown>,
        { $set: { role, updated_at: new Date() } }
      );
    } else {
      await col("target_assignments").insertOne({
        project_id: req.params.id,
        user_id: userId,
        target_url: targetUrl,
        role,
        assigned_by: (req as unknown as { session: { userId: string } }).session.userId,
        created_at: new Date(),
        updated_at: new Date(),
      });
    }

    logger.info({ userId, targetUrl, role }, "User assigned to target");
    res.json({ ok: true, message: `${userId} assigned as ${role} to ${targetUrl}` });
  } catch (err) {
    logger.error({ err }, "Assign user error");
    res.status(500).json({ error: "Failed to assign user" });
  }
});

// GET /projects/:id/members — List members of a project
router.get("/projects/:id/members", requireAuth, async (req, res) => {
  try {
    const members = await col("target_assignments")
      .find({ project_id: req.params.id })
      .toArray() as Array<Record<string, unknown>>;

    const enriched = await Promise.all(members.map(async (m) => {
      const user = await col("users").findOne({
        _id: new ObjectId(String(m["user_id"])),
      } as Record<string, unknown>) as Record<string, unknown> | null;

      return {
        userId: m["user_id"],
        username: user?.["username"] ?? "unknown",
        email: user?.["email"] ?? "",
        targetUrl: m["target_url"],
        role: m["role"],
        assignedAt: m["created_at"],
      };
    }));

    res.json(enriched);
  } catch (err) {
    logger.error({ err }, "List members error");
    res.status(500).json({ error: "Failed to list members" });
  }
});

// DELETE /projects/:id/members/:userId — Remove user from project
router.delete("/projects/:id/members/:userId", requireAdmin, async (req, res) => {
  try {
    await col("target_assignments").deleteMany({
      project_id: req.params.id,
      user_id: req.params.userId,
    } as Record<string, unknown>);

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to remove member" });
  }
});

// PATCH /users/:id/role — Change user global role (admin action)
router.patch("/users/:id/role", requireAdmin, async (req, res) => {
  try {
    const { role } = req.body as { role?: string };
    if (!role || !ROLES.includes(role)) {
      return res.status(400).json({ error: `Role must be: ${ROLES.join(", ")}` });
    }

    await col("users").updateOne(
      { _id: new ObjectId(String(req.params.id)) } as Record<string, unknown>,
      { $set: { role, updated_at: new Date() } }
    );

    logger.info({ userId: req.params.id, role }, "User role updated");
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to update role" });
  }
});

// Middleware: scope findings list to assigned targets
export async function scopeToAssignedTargets(userId: string, userRole: string) {
  if (userRole === "admin") return {};

  const assignments = await col("target_assignments")
    .find({ user_id: userId })
    .toArray() as Array<Record<string, unknown>>;

  const targetUrls = assignments.map(a => String(a["target_url"]));
  return targetUrls.length > 0 ? { target_url: { $in: targetUrls } } : { target_url: "__none__" };
}

export default router;
