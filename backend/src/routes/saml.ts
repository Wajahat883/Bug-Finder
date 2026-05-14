/**
 * SAML 2.0 SSO — enterprise identity provider integration.
 * Supports Okta, Azure AD, OneLogin, and any SAML 2.0 IdP.
 * Uses @node-saml/node-saml (install separately).
 */
import { Router } from "express";
import { col, ObjectId } from "../lib/db";
import { errorResponse } from "../lib/response";
import { logger } from "../lib/logger";
import { auditFromReq } from "../lib/audit";

const router = Router();

const SAML_CONFIG = {
  callbackUrl:    process.env["SAML_CALLBACK_URL"]    ?? "http://localhost:5000/api/auth/saml/callback",
  entryPoint:     process.env["SAML_ENTRY_POINT"]     ?? "",
  issuer:         process.env["SAML_ISSUER"]          ?? "bugfinder",
  cert:           process.env["SAML_IDP_CERT"]        ?? "",
  privateKey:     process.env["SAML_PRIVATE_KEY"]     ?? "",
  signatureAlgorithm: "sha256" as const,
  identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
};

async function getSaml() {
  try {
    const { SAML } = await import("@node-saml/node-saml") as typeof import("@node-saml/node-saml");
    return new SAML(SAML_CONFIG as unknown as ConstructorParameters<typeof SAML>[0]);
  } catch {
    return null;
  }
}

// GET /api/auth/saml/metadata — SP metadata for IdP configuration
router.get("/api/auth/saml/metadata", async (req, res) => {
  const saml = await getSaml();
  if (!saml) {
    return errorResponse(res, 501, "Not Implemented", "SAML is not enabled. Install @node-saml/node-saml.");
  }
  try {
    const metadata = saml.generateServiceProviderMetadata(null, null);
    res.contentType("application/xml").send(metadata);
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error", "Failed to generate SAML metadata");
  }
});

// GET /api/auth/saml/login — redirect to IdP for authentication
router.get("/api/auth/saml/login", async (req, res) => {
  const saml = await getSaml();
  if (!saml) {
    return errorResponse(res, 501, "Not Implemented", "SAML is not enabled.");
  }
  try {
    const url = await saml.getAuthorizeUrlAsync("", req.ip ?? "", {});
    res.redirect(url);
  } catch (err) {
    logger.error({ err }, "SAML login redirect error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

// POST /api/auth/saml/callback — IdP posts SAML response here
router.post("/api/auth/saml/callback", async (req, res) => {
  const saml = await getSaml();
  if (!saml) {
    return errorResponse(res, 501, "Not Implemented", "SAML is not enabled.");
  }

  try {
    const { profile } = await saml.validatePostResponseAsync(req.body as Record<string, string>);
    if (!profile) return errorResponse(res, 401, "SAML Authentication Failed", "No profile in SAML response");

    const email = String(profile["nameID"] ?? profile["email"] ?? "");
    const firstName = String(profile["firstName"] ?? profile["givenName"] ?? "SAML");
    const lastName = String(profile["lastName"] ?? profile["surname"] ?? "User");
    const groups = (profile["groups"] as string[] | undefined) ?? [];

    if (!email) return errorResponse(res, 400, "Bad SAML Response", "No email in SAML assertion");

    // Upsert user
    let user = await col("users").findOne({ email }) as Record<string, unknown> | null;
    if (!user) {
      const id = new ObjectId();
      const username = email.split("@")[0].replace(/[^a-z0-9_]/gi, "_").toLowerCase();
      const role = groups.some(g => g.toLowerCase().includes("admin")) ? "admin"
        : groups.some(g => g.toLowerCase().includes("senior")) ? "senior"
        : "analyst";

      await col("users").insertOne({
        _id: id, username, email, password: "", role,
        first_name: firstName, last_name: lastName,
        sso_provider: "saml", sso_groups: groups,
        created_at: new Date(), updated_at: new Date(),
      });
      user = { _id: id, username, email, role };
    }

    const session = (req as unknown as { session: Record<string, unknown> }).session;
    session["userId"] = String(user["_id"]);
    session["username"] = String(user["username"]);
    session["role"] = String(user["role"] ?? "analyst");

    await auditFromReq(req, "user.saml_login", "users", String(user["_id"]), { email });

    // Redirect to dashboard
    res.redirect("/dashboard");
  } catch (err) {
    logger.error({ err }, "SAML callback error");
    errorResponse(res, 401, "SAML Authentication Failed", err instanceof Error ? err.message : "Unknown error");
  }
});

export default router;
