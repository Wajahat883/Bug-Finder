import { Router } from "express";
import crypto from "crypto";
import { col, ObjectId } from "../lib/db";
import { logger } from "../lib/logger";

const router = Router();

interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userinfoEndpoint?: string;
}

function getProviderConfig(provider: "okta" | "azure" | "onelogin" | "google" | "oidc"): OidcConfig | null {
  const baseUrl = process.env["APP_URL"] ?? "http://localhost:5000";

  switch (provider) {
    case "google":
      if (!process.env["GOOGLE_CLIENT_ID"]) return null;
      return {
        issuer: "https://accounts.google.com",
        clientId: process.env["GOOGLE_CLIENT_ID"],
        clientSecret: process.env["GOOGLE_CLIENT_SECRET"] ?? "",
        redirectUri: `${baseUrl}/api/auth/oidc/google/callback`,
        scopes: "openid email profile",
        authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenEndpoint: "https://oauth2.googleapis.com/token",
        userinfoEndpoint: "https://www.googleapis.com/oauth2/v2/userinfo",
      };

    case "okta":
      if (!process.env["OKTA_DOMAIN"] || !process.env["OKTA_CLIENT_ID"]) return null;
      const oktaDomain = process.env["OKTA_DOMAIN"];
      return {
        issuer: `https://${oktaDomain}`,
        clientId: process.env["OKTA_CLIENT_ID"],
        clientSecret: process.env["OKTA_CLIENT_SECRET"] ?? "",
        redirectUri: `${baseUrl}/api/auth/oidc/okta/callback`,
        scopes: "openid email profile groups",
        authorizationEndpoint: `https://${oktaDomain}/oauth2/v1/authorize`,
        tokenEndpoint: `https://${oktaDomain}/oauth2/v1/token`,
        userinfoEndpoint: `https://${oktaDomain}/oauth2/v1/userinfo`,
      };

    case "azure":
      if (!process.env["AZURE_TENANT_ID"] || !process.env["AZURE_CLIENT_ID"]) return null;
      const tenantId = process.env["AZURE_TENANT_ID"];
      return {
        issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
        clientId: process.env["AZURE_CLIENT_ID"],
        clientSecret: process.env["AZURE_CLIENT_SECRET"] ?? "",
        redirectUri: `${baseUrl}/api/auth/oidc/azure/callback`,
        scopes: "openid email profile User.Read",
        authorizationEndpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
        tokenEndpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
        userinfoEndpoint: "https://graph.microsoft.com/v1.0/me",
      };

    case "onelogin":
      if (!process.env["ONELOGIN_DOMAIN"] || !process.env["ONELOGIN_CLIENT_ID"]) return null;
      const olDomain = process.env["ONELOGIN_DOMAIN"];
      return {
        issuer: `https://${olDomain}.onelogin.com/oidc/2`,
        clientId: process.env["ONELOGIN_CLIENT_ID"],
        clientSecret: process.env["ONELOGIN_CLIENT_SECRET"] ?? "",
        redirectUri: `${baseUrl}/api/auth/oidc/onelogin/callback`,
        scopes: "openid email profile",
        authorizationEndpoint: `https://${olDomain}.onelogin.com/oidc/2/auth`,
        tokenEndpoint: `https://${olDomain}.onelogin.com/oidc/2/token`,
        userinfoEndpoint: `https://${olDomain}.onelogin.com/oidc/2/me`,
      };

    case "oidc":
      // Generic OIDC — use env vars
      if (!process.env["OIDC_ISSUER"] || !process.env["OIDC_CLIENT_ID"]) return null;
      return {
        issuer: process.env["OIDC_ISSUER"],
        clientId: process.env["OIDC_CLIENT_ID"],
        clientSecret: process.env["OIDC_CLIENT_SECRET"] ?? "",
        redirectUri: `${baseUrl}/api/auth/oidc/generic/callback`,
        scopes: process.env["OIDC_SCOPES"] ?? "openid email profile",
        authorizationEndpoint: process.env["OIDC_AUTH_ENDPOINT"],
        tokenEndpoint: process.env["OIDC_TOKEN_ENDPOINT"],
        userinfoEndpoint: process.env["OIDC_USERINFO_ENDPOINT"],
      };

    default:
      return null;
  }
}

function buildAuthorizeUrl(config: OidcConfig, state: string, nonce: string): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scopes,
    state,
    nonce,
  });
  return `${config.authorizationEndpoint}?${params.toString()}`;
}

// Generic OIDC login — /auth/oidc/:provider
router.get("/auth/oidc/:provider", (req, res) => {
  const provider = req.params.provider as "okta" | "azure" | "onelogin" | "google" | "oidc";
  const config = getProviderConfig(provider);

  if (!config) {
    return res.status(400).json({
      error: `OIDC provider "${provider}" not configured. Set required env vars: ${
        provider === "okta" ? "OKTA_DOMAIN, OKTA_CLIENT_ID" :
        provider === "azure" ? "AZURE_TENANT_ID, AZURE_CLIENT_ID" :
        provider === "onelogin" ? "ONELOGIN_DOMAIN, ONELOGIN_CLIENT_ID" :
        provider === "google" ? "GOOGLE_CLIENT_ID" :
        "OIDC_ISSUER, OIDC_CLIENT_ID"
      }`,
    });
  }

  const state = crypto.randomBytes(32).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");

  (req as unknown as { session: Record<string, unknown> }).session["oidc_state"] = state;
  (req as unknown as { session: Record<string, unknown> }).session["oidc_nonce"] = nonce;
  (req as unknown as { session: Record<string, unknown> }).session["oidc_provider"] = provider;

  const url = buildAuthorizeUrl(config, state, nonce);
  res.redirect(url);
});

// Generic OIDC callback — /auth/oidc/:provider/callback
router.get("/auth/oidc/:provider/callback", async (req, res) => {
  const session = (req as unknown as { session: Record<string, unknown> }).session;
  const provider = (session["oidc_provider"] as string) ?? req.params.provider;
  const config = getProviderConfig(provider as any);

  if (!config || !config.tokenEndpoint) {
    return res.redirect("/login?error=oidc_not_configured");
  }

  const { code, state, error } = req.query as Record<string, string>;
  if (error || !code) return res.redirect("/login?error=oidc_denied");

  try {
    const tokenRes = await fetch(config.tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: config.clientId,
        client_secret: config.clientSecret,
        redirect_uri: config.redirectUri,
      }),
    });

    if (!tokenRes.ok) throw new Error(`Token exchange failed: ${tokenRes.status}`);
    const tokens = await tokenRes.json() as Record<string, unknown>;

    const userinfoUrl = config.userinfoEndpoint || `${config.issuer}/userinfo`;
    const userRes = await fetch(userinfoUrl, {
      headers: { Authorization: `Bearer ${tokens["access_token"]}` },
    });

    if (!userRes.ok) throw new Error(`Userinfo fetch failed: ${userRes.status}`);
    const profile = await userRes.json() as Record<string, unknown>;

    const email = String(profile["email"] ?? profile["mail"] ?? profile["userPrincipalName"] ?? "");
    const name = String(profile["name"] ?? profile["displayName"] ?? email);
    const sub = String(profile["sub"] ?? profile["id"] ?? "");

    if (!email) return res.redirect("/login?error=no_email");

    let user = await col("users").findOne({ email }) as Record<string, unknown> | null;
    if (!user) {
      const insert = await col("users").insertOne({
        email,
        username: email.split("@")[0],
        first_name: name.split(" ")[0] ?? "",
        last_name: name.split(" ").slice(1).join(" ") ?? "",
        role: "analyst",
        oauth_provider: provider,
        oauth_id: sub,
        created_at: new Date(),
        updated_at: new Date(),
      });
      user = await col("users").findOne({ _id: insert.insertedId }) as Record<string, unknown>;
    } else if (!user["oauth_id"]) {
      await col("users").updateOne(
        { _id: user["_id"] } as Record<string, unknown>,
        { $set: { oauth_provider: provider, oauth_id: sub } }
      );
    }

    session["userId"] = String(user["_id"]);
    session["username"] = String(user["username"] ?? email);
    session["role"] = String(user["role"] ?? "analyst");

    res.redirect("/dashboard");
  } catch (err) {
    logger.error({ err, provider }, "OIDC callback error");
    res.redirect("/login?error=oidc_failed");
  }
});

// GET /auth/oidc/status — Check which providers are configured
router.get("/auth/oidc/status", (_req, res) => {
  const providers = {
    google: !!getProviderConfig("google"),
    okta: !!getProviderConfig("okta"),
    azure: !!getProviderConfig("azure"),
    onelogin: !!getProviderConfig("onelogin"),
    oidc: !!getProviderConfig("oidc"),
  };

  const active = Object.entries(providers).filter(([, v]) => v).map(([k]) => k);

  res.json({
    configured: active.length > 0,
    providers: active,
    all: providers,
  });
});

export default router;
