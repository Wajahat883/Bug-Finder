/**
 * OIDC / SAML SSO integration
 *
 * Implements generic OpenID Connect (Authorization Code + PKCE) and
 * SAML 2.0 SP-initiated SSO so enterprise customers can use their IdP
 * (Okta, Azure AD, Google Workspace, Ping, Auth0, Keycloak…).
 *
 * OIDC flow (stateless PKCE — no session state needed during redirect):
 *   GET  /auth/oidc/providers              — list configured providers
 *   GET  /auth/oidc/:provider/authorize    — redirect to IdP
 *   GET  /auth/oidc/:provider/callback     — exchange code, set session
 *
 * SAML 2.0 SP-initiated flow:
 *   GET  /auth/saml/:provider/metadata     — SP metadata XML (give to IdP)
 *   GET  /auth/saml/:provider/login        — redirect to IdP SSO URL
 *   POST /auth/saml/:provider/acs          — Assertion Consumer Service
 *
 * Configuration via environment variables:
 *   OIDC_PROVIDERS=json-array (see below)
 *   SAML_PROVIDERS=json-array (see below)
 *
 * OIDC_PROVIDERS JSON shape:
 *   [{ "id": "okta", "name": "Okta", "issuer": "https://...", "client_id": "...",
 *      "client_secret": "...", "scopes": "openid email profile",
 *      "authorization_endpoint": "...", "token_endpoint": "...",
 *      "userinfo_endpoint": "...", "default_role": "analyst" }]
 *
 * SAML_PROVIDERS JSON shape:
 *   [{ "id": "azure", "name": "Azure AD", "entry_point": "https://...",
 *      "issuer": "https://...", "cert": "BASE64-CERT-NO-HEADERS",
 *      "default_role": "analyst" }]
 */

import { Router } from "express";
import crypto from "crypto";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

const router = Router();

interface OidcProvider {
  id: string;
  name: string;
  issuer: string;
  client_id: string;
  client_secret: string;
  scopes: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  default_role: string;
}

interface SamlProvider {
  id: string;
  name: string;
  entry_point: string;
  issuer: string;
  cert: string;           // IdP signing certificate (PEM body, no headers)
  default_role: string;
}

function loadOidcProviders(): OidcProvider[] {
  const raw = process.env["OIDC_PROVIDERS"];
  if (!raw) return [];
  try { return JSON.parse(raw) as OidcProvider[]; } catch {
    logger.warn("OIDC_PROVIDERS env var is not valid JSON — OIDC SSO disabled");
    return [];
  }
}

function loadSamlProviders(): SamlProvider[] {
  const raw = process.env["SAML_PROVIDERS"];
  if (!raw) return [];
  try { return JSON.parse(raw) as SamlProvider[]; } catch {
    logger.warn("SAML_PROVIDERS env var is not valid JSON — SAML SSO disabled");
    return [];
  }
}

const appUrl = () => process.env["APP_URL"] ?? "http://localhost:3000";

// ── List configured providers ─────────────────────────────────────────────────

router.get("/auth/oidc/providers", (_req, res) => {
  const oidcProviders = loadOidcProviders().map(p => ({ id: p.id, name: p.name, protocol: "oidc" }));
  const samlProviders = loadSamlProviders().map(p => ({ id: p.id, name: p.name, protocol: "saml" }));
  res.json({ providers: [...oidcProviders, ...samlProviders] });
});

// ── OIDC: Authorization Code + PKCE ──────────────────────────────────────────

router.get("/auth/oidc/:provider/authorize", (req, res) => {
  const providers = loadOidcProviders();
  const provider = providers.find(p => p.id === req.params.provider);
  if (!provider) return res.status(404).json({ error: "OIDC provider not configured" });

  // Generate PKCE code verifier and challenge
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

  // Generate state parameter (CSRF protection)
  const state = crypto.randomBytes(16).toString("hex");

  // Store code_verifier and state in a short-lived DB record (30 min TTL)
  const now = new Date();
  col("oidc_pkce_state").insertOne({
    state,
    code_verifier: codeVerifier,
    provider_id: provider.id,
    created_at: now,
    expires_at: new Date(now.getTime() + 30 * 60 * 1000),
  }).catch(err => logger.warn({ err }, "Failed to store PKCE state"));

  const redirectUri = `${appUrl()}/api/auth/oidc/${provider.id}/callback`;
  const params = new URLSearchParams({
    response_type: "code",
    client_id: provider.client_id,
    redirect_uri: redirectUri,
    scope: provider.scopes || "openid email profile",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });

  res.redirect(`${provider.authorization_endpoint}?${params.toString()}`);
});

router.get("/auth/oidc/:provider/callback", async (req, res) => {
  const providers = loadOidcProviders();
  const provider = providers.find(p => p.id === req.params.provider);
  if (!provider) return res.redirect(`/login?error=oidc_provider_not_found`);

  const { code, state, error: oidcError } = req.query as Record<string, string>;

  if (oidcError) {
    logger.warn({ oidcError, provider: provider.id }, "OIDC error from IdP");
    return res.redirect(`/login?error=${encodeURIComponent(oidcError)}`);
  }

  if (!code || !state) return res.redirect("/login?error=missing_params");

  try {
    // Retrieve PKCE state
    const pkceRecord = await col("oidc_pkce_state").findOne({
      state, provider_id: provider.id,
    } as Record<string, unknown>) as Record<string, unknown> | null;

    if (!pkceRecord) return res.redirect("/login?error=invalid_state");
    if (new Date(pkceRecord["expires_at"] as string) < new Date()) {
      return res.redirect("/login?error=state_expired");
    }

    // Delete used state record immediately (one-time use)
    await col("oidc_pkce_state").deleteOne({ state, provider_id: provider.id } as Record<string, unknown>);

    const redirectUri = `${appUrl()}/api/auth/oidc/${provider.id}/callback`;

    // Exchange code for tokens
    const tokenResp = await fetch(provider.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: provider.client_id,
        client_secret: provider.client_secret,
        code_verifier: String(pkceRecord["code_verifier"]),
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (!tokenResp.ok) {
      const errBody = await tokenResp.text().catch(() => "");
      logger.warn({ status: tokenResp.status, body: errBody, provider: provider.id }, "OIDC token exchange failed");
      return res.redirect("/login?error=token_exchange_failed");
    }

    const tokens = await tokenResp.json() as Record<string, unknown>;
    const accessToken = String(tokens["access_token"] ?? "");

    if (!accessToken) return res.redirect("/login?error=no_access_token");

    // Fetch user profile from userinfo endpoint
    const userinfoResp = await fetch(provider.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(8000),
    });

    if (!userinfoResp.ok) return res.redirect("/login?error=userinfo_failed");

    const profile = await userinfoResp.json() as Record<string, unknown>;
    const email = String(profile["email"] ?? "").toLowerCase().trim();
    const name = String(profile["name"] ?? profile["preferred_username"] ?? email);
    const sub = String(profile["sub"] ?? "");

    if (!email) return res.redirect("/login?error=no_email_in_profile");

    // Upsert user — find by email or by OIDC sub+provider
    let user = await col("users").findOne({ email } as Record<string, unknown>) as Record<string, unknown> | null;

    if (!user) {
      const ins = await col("users").insertOne({
        email,
        username: email.split("@")[0]!.replace(/[^a-z0-9_]/gi, "_").toLowerCase(),
        first_name: name.split(" ")[0] ?? name,
        last_name: name.split(" ").slice(1).join(" ") || "",
        role: provider.default_role || "analyst",
        oauth_provider: `oidc:${provider.id}`,
        oauth_sub: sub,
        email_verified: !!(profile["email_verified"]),
        avatar_url: profile["picture"] ?? null,
        created_at: new Date(),
        updated_at: new Date(),
      });
      user = await col("users").findOne({ _id: ins.insertedId } as Record<string, unknown>) as Record<string, unknown>;
    } else {
      // Update OAuth metadata on existing user
      await col("users").updateOne(
        { email } as Record<string, unknown>,
        { $set: { oauth_provider: `oidc:${provider.id}`, oauth_sub: sub, updated_at: new Date() } }
      );
    }

    if (!user) return res.redirect("/login?error=user_creation_failed");

    // Establish session
    const sess = req.session as unknown as Record<string, unknown>;
    sess["userId"] = String(user["_id"]);
    sess["username"] = String(user["username"] ?? email);
    sess["role"] = String(user["role"] ?? provider.default_role ?? "analyst");
    sess["sso_provider"] = provider.id;

    logger.info({ email, provider: provider.id }, "OIDC SSO login successful");
    res.redirect("/dashboard");
  } catch (err) {
    logger.error({ err, provider: provider.id }, "OIDC callback error");
    res.redirect("/login?error=oidc_callback_failed");
  }
});

// ── SAML 2.0 SP-initiated flow ────────────────────────────────────────────────

// SP metadata — give this XML to the IdP administrator
router.get("/auth/saml/:provider/metadata", (req, res) => {
  const providers = loadSamlProviders();
  const provider = providers.find(p => p.id === req.params.provider);
  if (!provider) return res.status(404).json({ error: "SAML provider not configured" });

  const spEntityId = `${appUrl()}/api/auth/saml/${provider.id}`;
  const acsUrl = `${appUrl()}/api/auth/saml/${provider.id}/acs`;

  const metadata = `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="${spEntityId}">
  <md:SPSSODescriptor
    AuthnRequestsSigned="false"
    WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${acsUrl}"
      index="1"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;

  res.setHeader("Content-Type", "application/xml");
  res.send(metadata);
});

// Redirect to IdP SSO URL
router.get("/auth/saml/:provider/login", (req, res) => {
  const providers = loadSamlProviders();
  const provider = providers.find(p => p.id === req.params.provider);
  if (!provider) return res.status(404).json({ error: "SAML provider not configured" });

  const acsUrl = `${appUrl()}/api/auth/saml/${provider.id}/acs`;
  const spEntityId = `${appUrl()}/api/auth/saml/${provider.id}`;
  const id = `_${crypto.randomBytes(16).toString("hex")}`;
  const instant = new Date().toISOString();

  // Build minimal AuthnRequest — deflate+base64 for HTTP-Redirect binding
  const authnRequest = `<?xml version="1.0"?>
<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${id}"
  Version="2.0"
  IssueInstant="${instant}"
  Destination="${provider.entry_point}"
  AssertionConsumerServiceURL="${acsUrl}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>${spEntityId}</saml:Issuer>
  <samlp:NameIDPolicy
    Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    AllowCreate="true"/>
</samlp:AuthnRequest>`;

  const deflated = Buffer.from(authnRequest);
  const encoded = deflated.toString("base64");
  const relayState = crypto.randomBytes(8).toString("hex");

  const params = new URLSearchParams({
    SAMLRequest: encoded,
    RelayState: relayState,
  });

  res.redirect(`${provider.entry_point}?${params.toString()}`);
});

// ACS — Assertion Consumer Service (receives SAML response from IdP)
router.post("/auth/saml/:provider/acs", async (req, res) => {
  const providers = loadSamlProviders();
  const provider = providers.find(p => p.id === req.params.provider);
  if (!provider) return res.redirect("/login?error=saml_provider_not_found");

  try {
    const samlResponse = req.body?.SAMLResponse as string | undefined;
    if (!samlResponse) return res.redirect("/login?error=missing_saml_response");

    // Decode and parse the SAML response XML
    const decoded = Buffer.from(samlResponse, "base64").toString("utf-8");

    // Signature verification: verify the IdP certificate signature
    // We do this by checking if the response XML contains a valid signature
    // using the configured certificate.
    const certPem = `-----BEGIN CERTIFICATE-----\n${provider.cert.replace(/\s+/g, "")}\n-----END CERTIFICATE-----`;

    // Extract signature value from XML
    const sigMatch = decoded.match(/<ds:SignatureValue[^>]*>([^<]+)<\/ds:SignatureValue>/);
    const signedInfoMatch = decoded.match(/<ds:SignedInfo[^>]*>([\s\S]*?)<\/ds:SignedInfo>/);

    if (!sigMatch || !signedInfoMatch) {
      logger.warn({ provider: provider.id }, "SAML response missing signature");
      return res.redirect("/login?error=saml_no_signature");
    }

    // Verify signature using Node.js crypto
    const signatureB64 = sigMatch[1]!.replace(/\s+/g, "");
    const signedInfoXml = `<ds:SignedInfo${signedInfoMatch[0].slice(12)}`;
    const verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(signedInfoXml, "utf-8");
    const signatureValid = verifier.verify(certPem, signatureB64, "base64");

    if (!signatureValid) {
      logger.warn({ provider: provider.id }, "SAML signature verification failed");
      return res.redirect("/login?error=saml_invalid_signature");
    }

    // Extract NameID (email) and attributes from assertion
    const nameIdMatch = decoded.match(/<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/);
    const email = nameIdMatch?.[1]?.trim().toLowerCase();
    if (!email) return res.redirect("/login?error=saml_no_nameid");

    // Extract optional display name from attributes
    const nameMatch = decoded.match(/Name="displayName"[^>]*>[\s\S]*?<saml:AttributeValue[^>]*>([^<]+)<\/saml:AttributeValue>/);
    const name = nameMatch?.[1]?.trim() ?? email;

    // Check assertion validity window (NotBefore / NotOnOrAfter)
    const notBeforeMatch = decoded.match(/NotBefore="([^"]+)"/);
    const notAfterMatch = decoded.match(/NotOnOrAfter="([^"]+)"/);
    const now = new Date();
    if (notBeforeMatch && new Date(notBeforeMatch[1]!) > now) {
      return res.redirect("/login?error=saml_not_yet_valid");
    }
    if (notAfterMatch && new Date(notAfterMatch[1]!) < now) {
      return res.redirect("/login?error=saml_assertion_expired");
    }

    // Upsert user
    let user = await col("users").findOne({ email } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!user) {
      const ins = await col("users").insertOne({
        email,
        username: email.split("@")[0]!.replace(/[^a-z0-9_]/gi, "_").toLowerCase(),
        first_name: name.split(" ")[0] ?? name,
        last_name: name.split(" ").slice(1).join(" ") || "",
        role: provider.default_role || "analyst",
        oauth_provider: `saml:${provider.id}`,
        email_verified: true,
        created_at: new Date(),
        updated_at: new Date(),
      });
      user = await col("users").findOne({ _id: ins.insertedId } as Record<string, unknown>) as Record<string, unknown>;
    } else {
      await col("users").updateOne(
        { email } as Record<string, unknown>,
        { $set: { oauth_provider: `saml:${provider.id}`, updated_at: new Date() } }
      );
    }

    if (!user) return res.redirect("/login?error=user_creation_failed");

    const sess = req.session as unknown as Record<string, unknown>;
    sess["userId"] = String(user["_id"]);
    sess["username"] = String(user["username"] ?? email);
    sess["role"] = String(user["role"] ?? provider.default_role ?? "analyst");
    sess["sso_provider"] = provider.id;

    logger.info({ email, provider: provider.id }, "SAML SSO login successful");
    res.redirect("/dashboard");
  } catch (err) {
    logger.error({ err, provider: provider.id }, "SAML ACS error");
    res.redirect("/login?error=saml_acs_failed");
  }
});

export default router;
