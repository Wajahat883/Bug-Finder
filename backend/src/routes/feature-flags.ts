/**
 * Feature Flags API — admin CRUD + per-user flag evaluation endpoint.
 */
import { Router, Request, Response, NextFunction } from "express";
import { requireAuth, requireAdmin } from "../middlewares/rbac";
import { listFlags, setFlag, isFlagEnabled, getFlag } from "../lib/feature-flags";
import { errorResponse } from "../lib/response";
import { logger } from "../lib/logger";

// ---------------------------------------------------------------------------
// Exported helpers — consumed by other routes that gate features
// ---------------------------------------------------------------------------

/**
 * Evaluate a feature flag for a specific user/tenant context.
 * Supports per-user overrides, per-tenant overrides, and global rollout %.
 */
export async function isFeatureEnabled(
  flagName: string,
  context?: { userId?: string; tenantId?: string }
): Promise<boolean> {
  try {
    return await isFlagEnabled(flagName, {
      userId: context?.userId,
      // Map tenantId → role lookup is handled inside isFlagEnabled via allowed_roles;
      // for tenant-level overrides we treat the tenantId as a userId-level override.
      ...(context?.tenantId ? { userId: context.userId ?? context.tenantId } : {}),
    });
  } catch {
    return false; // fail open
  }
}

/**
 * Route middleware — responds 404 when the named flag is disabled for the
 * requesting user so the feature appears non-existent to unauthorised callers.
 */
export function requireFeatureFlag(flagName: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const session = (req as unknown as { session: { userId?: string; tenantId?: string } }).session;
    const enabled = await isFeatureEnabled(flagName, {
      userId: session?.userId,
      tenantId: session?.tenantId,
    });
    if (!enabled) return res.status(404).json({ error: "Feature not available" });
    next();
  };
}

const router = Router();

// GET /api/feature-flags — list all flags (admin only)
router.get("/feature-flags", requireAdmin, async (_req, res) => {
  try {
    const flags = await listFlags();
    res.json(flags);
  } catch (err) {
    logger.error({ err }, "List feature flags error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

// GET /api/feature-flags/me — flags enabled for current user (any auth user)
router.get("/feature-flags/me", requireAuth, async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const allFlags = await listFlags();
    const result: Record<string, boolean> = {};
    for (const flag of allFlags) {
      result[flag.name] = await isFlagEnabled(flag.name, {
        userId: session.userId,
        role: session.role,
      });
    }
    res.json(result);
  } catch (err) {
    logger.error({ err }, "Get user feature flags error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

// PATCH /api/feature-flags/:name — update a flag (admin only)
router.patch("/feature-flags/:name", requireAdmin, async (req, res) => {
  try {
    const name = String(req.params["name"]);
    const { enabled, allowed_roles, allowed_user_ids, rollout_percent, description } = req.body as {
      enabled?: boolean;
      allowed_roles?: string[];
      allowed_user_ids?: string[];
      rollout_percent?: number;
      description?: string;
    };

    await setFlag(name, {
      ...(enabled !== undefined ? { enabled } : {}),
      ...(allowed_roles !== undefined ? { allowed_roles } : {}),
      ...(allowed_user_ids !== undefined ? { allowed_user_ids } : {}),
      ...(rollout_percent !== undefined ? { rollout_percent } : {}),
      ...(description !== undefined ? { description } : {}),
    });

    const updated = await getFlag(String(name));
    res.json(updated);
  } catch (err) {
    logger.error({ err }, "Update feature flag error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

// POST /api/feature-flags — create a new flag (admin only)
router.post("/feature-flags", requireAdmin, async (req, res) => {
  try {
    const { name, enabled = false, description, allowed_roles, rollout_percent } = req.body as {
      name: string; enabled?: boolean; description?: string;
      allowed_roles?: string[]; rollout_percent?: number;
    };
    if (!name || !/^[a-z_]+$/.test(name)) {
      return errorResponse(res, 422, "Validation Failed", "name must be lowercase snake_case");
    }
    await setFlag(name, { enabled, description, allowed_roles, rollout_percent });
    res.status(201).json(await getFlag(name));
  } catch (err) {
    logger.error({ err }, "Create feature flag error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

// GET /api/feature-flags/status — current flag values for the authenticated user
router.get("/feature-flags/status", requireAuth, async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId?: string; role?: string; tenantId?: string } }).session;
    const allFlags = await listFlags();
    const result: Array<{ name: string; enabled: boolean; description?: string }> = [];
    for (const flag of allFlags) {
      const enabled = await isFlagEnabled(flag.name, {
        userId: session.userId,
        role: session.role,
      });
      result.push({ name: flag.name, enabled, description: flag.description });
    }
    res.json({ flags: result, user_id: session.userId ?? null });
  } catch (err) {
    logger.error({ err }, "Get feature flags status error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

export default router;
