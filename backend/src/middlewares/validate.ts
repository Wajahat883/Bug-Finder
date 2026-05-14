/**
 * Zod request validation middleware.
 * Usage: router.post("/route", validate({ body: MySchema }), handler)
 */
import type { Request, Response, NextFunction } from "express";
import { z, ZodSchema } from "zod";
import { errorResponse } from "../lib/response";

interface ValidateOptions {
  body?: ZodSchema;
  query?: ZodSchema;
  params?: ZodSchema;
}

export function validate(schemas: ValidateOptions) {
  return (req: Request, res: Response, next: NextFunction) => {
    const errors: string[] = [];

    if (schemas.body) {
      const result = schemas.body.safeParse(req.body);
      if (!result.success) {
        errors.push(...result.error.issues.map(i => `body.${i.path.join(".")}: ${i.message}`));
      } else {
        req.body = result.data;
      }
    }

    if (schemas.query) {
      const result = schemas.query.safeParse(req.query);
      if (!result.success) {
        errors.push(...result.error.issues.map(i => `query.${i.path.join(".")}: ${i.message}`));
      }
    }

    if (schemas.params) {
      const result = schemas.params.safeParse(req.params);
      if (!result.success) {
        errors.push(...result.error.issues.map(i => `params.${i.path.join(".")}: ${i.message}`));
      }
    }

    if (errors.length > 0) {
      errorResponse(res, 422, "Validation Failed", errors.join("; "), { errors });
      return;
    }

    next();
  };
}

// ── Common reusable schemas ───────────────────────────────────────────────────

export const PasswordSchema = z
  .string()
  .min(12, "Password must be at least 12 characters")
  .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
  .regex(/[a-z]/, "Password must contain at least one lowercase letter")
  .regex(/[0-9]/, "Password must contain at least one number")
  .regex(/[^A-Za-z0-9]/, "Password must contain at least one special character");

export const EmailSchema = z.string().email("Invalid email address").toLowerCase();

export const ObjectIdSchema = z.string().regex(/^[a-f\d]{24}$/i, "Invalid ID format");

export const PaginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(200).default(20),
});

export const RegisterSchema = z.object({
  firstName: z.string().min(1).max(50),
  lastName: z.string().min(1).max(50),
  email: EmailSchema,
  password: PasswordSchema,
});

export const LoginSchema = z.object({
  email: EmailSchema,
  password: z.string().min(1, "Password is required"),
  remember_me: z.boolean().optional(),
});

export const TriageSchema = z.object({
  status: z.enum(["open", "confirmed", "false_positive", "suppressed", "needs_review"]),
  fp_reason: z.string().optional(),
  fp_evidence: z.string().max(2000).optional(),
  triage_notes: z.string().max(2000).optional(),
  expiry_days: z.number().int().min(1).max(365).optional(),
  suppress_days: z.number().int().min(1).max(365).optional(),
});

export const FindingUpdateSchema = z.object({
  validation_status: z.enum(["confirmed", "false_positive", "needs_review", "real", "informational"]).optional(),
  notes: z.string().max(5000).optional(),
  fp_reason: z.string().optional(),
  suppress_globally: z.boolean().optional(),
});
