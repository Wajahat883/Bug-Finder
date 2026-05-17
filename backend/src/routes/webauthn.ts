/**
 * WebAuthn / Passkey routes — FIDO2 registration and authentication.
 * Uses @simplewebauthn/server. Falls back gracefully if not installed.
 */
import { Router } from "express";
import { col, ObjectId } from "../lib/db";
import { requireAuth } from "../middlewares/rbac";
import { errorResponse } from "../lib/response";
import { logger } from "../lib/logger";

const router = Router();

const RP_NAME = process.env["WEBAUTHN_RP_NAME"] ?? "Bug Finder";
const RP_ID = process.env["WEBAUTHN_RP_ID"] ?? "localhost";
const ORIGIN = process.env["WEBAUTHN_ORIGIN"] ?? "http://localhost:5173";

function getSession(req: unknown) {
  return (req as { session: Record<string, unknown> }).session;
}

// POST /api/webauthn/register/begin — start passkey registration
router.post("/webauthn/register/begin", requireAuth, async (req, res) => {
  try {
    let generateRegistrationOptions: (opts: unknown) => Promise<unknown>;
    try {
      ({ generateRegistrationOptions } = await import("@simplewebauthn/server") as typeof import("@simplewebauthn/server"));
    } catch {
      return errorResponse(res, 501, "Not Implemented", "WebAuthn is not enabled on this server. Install @simplewebauthn/server.");
    }

    const session = getSession(req);
    const userId = session["userId"] as string;
    const user = await col("users").findOne({ _id: new ObjectId(userId) }) as Record<string, unknown> | null;
    if (!user) return errorResponse(res, 404, "User Not Found");

    const existingCredentials = await col("webauthn_credentials")
      .find({ user_id: userId })
      .toArray() as unknown as Array<{ credential_id: string; transports: string[] }>;

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: Buffer.from(userId),
      userName: String(user["email"] ?? user["username"]),
      userDisplayName: `${user["first_name"] ?? ""} ${user["last_name"] ?? ""}`.trim(),
      excludeCredentials: existingCredentials.map(c => ({
        id: Buffer.from(c.credential_id, "base64url"),
        transports: c.transports ?? [],
      })),
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "preferred",
      },
    });

    // Store challenge in session
    session["webauthn_challenge"] = (options as Record<string, unknown>)["challenge"];
    res.json(options);
  } catch (err) {
    logger.error({ err }, "WebAuthn register begin error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

// POST /api/webauthn/register/complete — finish passkey registration
router.post("/webauthn/register/complete", requireAuth, async (req, res) => {
  try {
    let verifyRegistrationResponse: (opts: unknown) => Promise<unknown>;
    try {
      ({ verifyRegistrationResponse } = await import("@simplewebauthn/server") as typeof import("@simplewebauthn/server"));
    } catch {
      return errorResponse(res, 501, "Not Implemented", "WebAuthn not available");
    }

    const session = getSession(req);
    const userId = session["userId"] as string;
    const expectedChallenge = session["webauthn_challenge"] as string;

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    }) as Record<string, unknown>;

    if (!verification["verified"]) {
      return errorResponse(res, 400, "Verification Failed", "WebAuthn registration could not be verified");
    }

    const info = verification["registrationInfo"] as Record<string, unknown>;
    const credentialId = Buffer.from(info["credentialID"] as Uint8Array).toString("base64url");
    const publicKey = Buffer.from(info["credentialPublicKey"] as Uint8Array).toString("base64");

    await col("webauthn_credentials").insertOne({
      user_id: userId,
      credential_id: credentialId,
      public_key: publicKey,
      counter: info["counter"] ?? 0,
      device_type: info["credentialDeviceType"] ?? "singleDevice",
      backed_up: info["credentialBackedUp"] ?? false,
      transports: req.body.response?.transports ?? [],
      created_at: new Date(),
    });

    await col("users").updateOne({ _id: new ObjectId(userId) }, { $set: { webauthn_enabled: true } });
    delete session["webauthn_challenge"];

    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "WebAuthn register complete error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

// POST /api/webauthn/authenticate/begin — start passkey login
router.post("/webauthn/authenticate/begin", async (req, res) => {
  try {
    let generateAuthenticationOptions: (opts: unknown) => Promise<unknown>;
    try {
      ({ generateAuthenticationOptions } = await import("@simplewebauthn/server") as typeof import("@simplewebauthn/server"));
    } catch {
      return errorResponse(res, 501, "Not Implemented", "WebAuthn not available");
    }

    const { email } = req.body as { email?: string };
    const user = email ? await col("users").findOne({ email }) as Record<string, unknown> | null : null;

    const credentials = user
      ? await col("webauthn_credentials").find({ user_id: String(user["_id"]) }).toArray() as unknown as Array<{ credential_id: string; transports: string[] }>
      : [];

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: credentials.map(c => ({
        id: Buffer.from(c.credential_id, "base64url"),
        transports: c.transports,
      })),
      userVerification: "preferred",
    });

    const session = getSession(req);
    session["webauthn_challenge"] = (options as Record<string, unknown>)["challenge"];
    if (user) session["webauthn_user_id"] = String(user["_id"]);
    res.json(options);
  } catch (err) {
    logger.error({ err }, "WebAuthn auth begin error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

// POST /api/webauthn/authenticate/complete — finish passkey login
router.post("/webauthn/authenticate/complete", async (req, res) => {
  try {
    let verifyAuthenticationResponse: (opts: unknown) => Promise<unknown>;
    try {
      ({ verifyAuthenticationResponse } = await import("@simplewebauthn/server") as typeof import("@simplewebauthn/server"));
    } catch {
      return errorResponse(res, 501, "Not Implemented", "WebAuthn not available");
    }

    const session = getSession(req);
    const expectedChallenge = session["webauthn_challenge"] as string;
    const userId = session["webauthn_user_id"] as string;

    const credId = req.body.id as string;
    const stored = await col("webauthn_credentials").findOne({ credential_id: credId }) as Record<string, unknown> | null;
    if (!stored) return errorResponse(res, 404, "Credential Not Found");

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: Buffer.from(String(stored["credential_id"]), "base64url"),
        credentialPublicKey: Buffer.from(String(stored["public_key"]), "base64"),
        counter: Number(stored["counter"] ?? 0),
      },
    }) as Record<string, unknown>;

    if (!verification["verified"]) {
      return errorResponse(res, 401, "Authentication Failed");
    }

    // Update counter
    const info = verification["authenticationInfo"] as Record<string, unknown>;
    await col("webauthn_credentials").updateOne(
      { credential_id: credId },
      { $set: { counter: info["newCounter"] } }
    );

    // Create authenticated session
    const user = await col("users").findOne({ _id: new ObjectId(String(stored["user_id"])) }) as Record<string, unknown> | null;
    if (!user) return errorResponse(res, 404, "User Not Found");

    session["userId"] = String(user["_id"]);
    session["username"] = String(user["username"]);
    session["role"] = String(user["role"] ?? "analyst");
    delete session["webauthn_challenge"];
    delete session["webauthn_user_id"];

    res.json({ ok: true, user: { id: session["userId"], username: session["username"], role: session["role"] } });
  } catch (err) {
    logger.error({ err }, "WebAuthn auth complete error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

// GET /api/webauthn/credentials — list user's registered passkeys
router.get("/webauthn/credentials", requireAuth, async (req, res) => {
  try {
    const session = getSession(req);
    const creds = await col("webauthn_credentials")
      .find({ user_id: session["userId"] })
      .project({ public_key: 0 })
      .toArray();
    res.json(creds);
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error");
  }
});

// DELETE /api/webauthn/credentials/:id — remove a passkey
router.delete("/webauthn/credentials/:id", requireAuth, async (req, res) => {
  try {
    const session = getSession(req);
    await col("webauthn_credentials").deleteOne({
      credential_id: req.params.id,
      user_id: session["userId"],
    });
    res.json({ ok: true });
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error");
  }
});

export default router;
