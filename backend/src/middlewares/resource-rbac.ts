/**
 * Resource-Level RBAC — restricts access to findings/scans/targets
 * based on the user's engagement membership.
 *
 * Analysts can only see resources that belong to engagements they are members of.
 * Admins and seniors bypass this check.
 */
import type { Request, Response, NextFunction } from "express";
import { col } from "../lib/db";
import { ObjectId } from "mongodb";
import { errorResponse } from "../lib/response";

declare module "express" {
  interface Request {
    allowedEngagementIds?: string[];
  }
}

const BYPASS_ROLES = new Set(["admin", "senior"]);

export async function resourceRbac(req: Request, res: Response, next: NextFunction): Promise<void> {
  const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
  if (!session?.userId) {
    errorResponse(res, 401, "Authentication Required");
    return;
  }

  // Admins and seniors see everything
  if (BYPASS_ROLES.has(session.role ?? "")) {
    req.allowedEngagementIds = undefined; // undefined = no filter
    return next();
  }

  try {
    // Fetch engagement memberships for this user
    const memberships = await col("project_members")
      .find({ user_id: session.userId, active: true })
      .project({ engagement_id: 1 })
      .toArray() as Array<{ engagement_id: string }>;

    req.allowedEngagementIds = memberships.map(m => String(m.engagement_id));
    next();
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error", "Failed to resolve engagement permissions");
  }
}

/**
 * Helper: build engagement scope filter for MongoDB queries.
 * Returns empty object (no filter) for admins/seniors.
 */
export function engagementScopeFilter(req: Request): Record<string, unknown> {
  const ids = req.allowedEngagementIds;
  if (!ids) return {}; // admin/senior bypass
  if (ids.length === 0) return { engagement_id: { $in: [] } }; // no access
  return { engagement_id: { $in: ids } };
}

/**
 * Check if user has access to a specific engagement.
 */
export async function canAccessEngagement(
  userId: string,
  role: string,
  engagementId: string
): Promise<boolean> {
  if (BYPASS_ROLES.has(role)) return true;
  const membership = await col("project_members").findOne({
    user_id: userId,
    engagement_id: engagementId,
    active: true,
  });
  return !!membership;
}
