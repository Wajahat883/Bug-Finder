import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Shield, KeyRound, CheckCircle2, XCircle, Loader2, Copy, QrCode, RefreshCw, Fingerprint, Trash2, UsbIcon } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface SecurityKey {
  id: string;
  name: string;
  created_at: string;
  last_used?: string | null;
}

export default function TwoFactorSetup() {
  const [step, setStep] = useState<"idle" | "setup" | "verify">("idle");
  const [code, setCode] = useState("");
  const [secret, setSecret] = useState("");
  const [otpauthUrl, setOtpAuthUrl] = useState("");
  const [registeringPasskey, setRegisteringPasskey] = useState(false);
  const [registeringSecurityKey, setRegisteringSecurityKey] = useState(false);
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: status } = useQuery<{ enabled: boolean }>({
    queryKey: ["/api/auth/2fa/status"],
    queryFn: () => fetch("/api/auth/2fa/status", { credentials: "include" }).then(r => r.json()),
    staleTime: 30000,
  });

  const { data: passkeys, refetch: refetchPasskeys } = useQuery<Array<{ _id: string; device_type: string; created_at: string; transports: string[] }>>({
    queryKey: ["/api/webauthn/credentials"],
    queryFn: () => fetch("/api/webauthn/credentials", { credentials: "include" }).then(r => r.json()),
    staleTime: 30000,
  });

  const { data: securityKeys, refetch: refetchSecurityKeys } = useQuery<SecurityKey[]>({
    queryKey: ["/api/webauthn/credentials/security-keys"],
    queryFn: () =>
      fetch("/api/webauthn/credentials", { credentials: "include" })
        .then(r => r.json())
        .then((items: unknown[]) =>
          (items as Array<Record<string, unknown>>).map(item => ({
            id: String(item["id"] ?? item["_id"] ?? ""),
            name: String(item["name"] ?? item["device_type"] ?? "Security Key"),
            created_at: String(item["created_at"] ?? ""),
            last_used: item["last_used"] ? String(item["last_used"]) : null,
          }))
        ),
    staleTime: 30000,
  });

  const removeSecurityKeyMutation = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/webauthn/credentials/${id}`, { method: "DELETE", credentials: "include" }).then(r => r.json()),
    onSuccess: () => { toast({ title: "Security key removed" }); refetchSecurityKeys(); refetchPasskeys(); },
    onError: () => toast({ title: "Failed to remove security key", variant: "destructive" }),
  });

  const registerSecurityKey = async () => {
    if (!navigator.credentials) {
      toast({ title: "WebAuthn not supported in this browser", variant: "destructive" });
      return;
    }
    setRegisteringSecurityKey(true);
    try {
      const beginResp = await fetch("/api/webauthn/register/begin", { method: "GET", credentials: "include" });
      if (!beginResp.ok) {
        toast({ title: "Server error starting security key registration", variant: "destructive" });
        return;
      }
      const { options } = await beginResp.json() as { options: PublicKeyCredentialCreationOptions };

      // Decode base64url challenge and user.id
      const decode = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
      const publicKey: PublicKeyCredentialCreationOptions = {
        ...options,
        challenge: decode(options.challenge as unknown as string),
        user: { ...options.user, id: decode(options.user.id as unknown as string) },
        excludeCredentials: options.excludeCredentials?.map(c => ({ ...c, id: decode(c.id as unknown as string) })),
      };

      const credential = await navigator.credentials.create({ publicKey });
      if (!credential) throw new Error("Credential creation returned null");

      // Encode for transport
      const cred = credential as PublicKeyCredential;
      const response = cred.response as AuthenticatorAttestationResponse;
      const toBase64url = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

      const completeResp = await fetch("/api/webauthn/register/complete", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: cred.id,
          rawId: toBase64url(cred.rawId),
          type: cred.type,
          response: {
            attestationObject: toBase64url(response.attestationObject),
            clientDataJSON: toBase64url(response.clientDataJSON),
          },
        }),
      });
      const result = await completeResp.json() as { ok?: boolean; error?: string };
      if (result.ok) {
        toast({ title: "Security key registered successfully" });
        refetchSecurityKeys();
        refetchPasskeys();
      } else {
        toast({ title: result.error ?? "Registration failed", variant: "destructive" });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Registration cancelled or failed";
      toast({ title: msg, variant: "destructive" });
    } finally {
      setRegisteringSecurityKey(false);
    }
  };

  const daysSince = (dateStr: string | null | undefined): string => {
    if (!dateStr) return "Never";
    const diff = Math.floor((Date.now() - new Date(dateStr).getTime()) / 86400000);
    return diff === 0 ? "Today" : `${diff} day${diff !== 1 ? "s" : ""} ago`;
  };

  const setupMutation = useMutation({
    mutationFn: () => fetch("/api/auth/2fa/setup", { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: (data: { secret: string; otpauth_url: string }) => {
      setSecret(data.secret);
      setOtpAuthUrl(data.otpauth_url);
      setStep("verify");
    },
    onError: () => toast({ title: "Failed to start 2FA setup", variant: "destructive" }),
  });

  const verifyMutation = useMutation({
    mutationFn: (code: string) =>
      fetch("/api/auth/2fa/verify", { method: "POST", credentials: "include", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code }) })
        .then(r => r.json()),
    onSuccess: (data: { ok: boolean }) => {
      if (data.ok) { toast({ title: "2FA enabled" }); setStep("idle"); setCode(""); qc.invalidateQueries({ queryKey: ["/api/auth/2fa/status"] }); }
      else toast({ title: "Invalid code", variant: "destructive" });
    },
  });

  const disableMutation = useMutation({
    mutationFn: () => fetch("/api/auth/2fa/disable", { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: () => { toast({ title: "2FA disabled" }); qc.invalidateQueries({ queryKey: ["/api/auth/2fa/status"] }); },
  });

  const deletePasskeyMutation = useMutation({
    mutationFn: (credId: string) =>
      fetch(`/api/webauthn/credentials/${credId}`, { method: "DELETE", credentials: "include" }).then(r => r.json()),
    onSuccess: () => { toast({ title: "Passkey removed" }); refetchPasskeys(); },
    onError: () => toast({ title: "Failed to remove passkey", variant: "destructive" }),
  });

  const copySecret = () => { navigator.clipboard.writeText(secret); toast({ title: "Secret copied" }); };

  const registerPasskey = async () => {
    setRegisteringPasskey(true);
    try {
      let startRegistration: (opts: unknown) => Promise<unknown>;
      try {
        ({ startRegistration } = await import("@simplewebauthn/browser") as typeof import("@simplewebauthn/browser"));
      } catch {
        toast({ title: "WebAuthn not available in this browser", variant: "destructive" });
        return;
      }
      const beginResp = await fetch("/api/webauthn/register/begin", { method: "POST", credentials: "include" });
      if (!beginResp.ok) { toast({ title: "Server error starting passkey registration", variant: "destructive" }); return; }
      const options = await beginResp.json();
      const attResp = await startRegistration(options);
      const completeResp = await fetch("/api/webauthn/register/complete", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(attResp),
      });
      const result = await completeResp.json() as { ok?: boolean; error?: string };
      if (result.ok) { toast({ title: "Passkey registered successfully" }); refetchPasskeys(); }
      else toast({ title: result.error ?? "Registration failed", variant: "destructive" });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Registration cancelled or failed";
      toast({ title: msg, variant: "destructive" });
    } finally {
      setRegisteringPasskey(false);
    }
  };

  const passkeyList = Array.isArray(passkeys) ? passkeys : [];

  const totpCard = (() => {
    if (status?.enabled) {
      return (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-green-400" /> Authenticator App (TOTP)
            </CardTitle>
            <CardDescription>Your account is protected with TOTP-based 2FA.</CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-green-400" />
              <Badge className="bg-green-500/10 text-green-400 border-green-500/20">Enabled</Badge>
            </div>
            <Button variant="outline" size="sm" onClick={() => disableMutation.mutate()} disabled={disableMutation.isPending} className="text-red-400 border-red-500/20 hover:bg-red-500/10">
              {disableMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : "Disable 2FA"}
            </Button>
          </CardContent>
        </Card>
      );
    }

    if (step === "verify") {
      return (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <QrCode className="w-5 h-5 text-purple-400" /> Verify 2FA Setup
            </CardTitle>
            <CardDescription>Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-start gap-4">
              <div className="bg-white p-3 rounded-lg">
                <img
                  src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(otpauthUrl)}`}
                  alt="2FA QR Code"
                  className="w-44 h-44"
                />
              </div>
              <div className="flex-1 space-y-2">
                <p className="text-xs font-semibold text-muted-foreground">Manual Setup Key</p>
                <div className="flex items-center gap-2">
                  <code className="text-xs bg-muted px-2 py-1 rounded font-mono break-all">{secret}</code>
                  <Button variant="ghost" size="sm" onClick={copySecret}><Copy className="w-3 h-3" /></Button>
                </div>
                <p className="text-[10px] text-muted-foreground">Enter this key manually if you cannot scan the QR code.</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Input
                placeholder="Enter 6-digit code"
                value={code}
                onChange={e => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                maxLength={6}
                className="font-mono text-lg tracking-widest w-40"
              />
              <Button onClick={() => verifyMutation.mutate(code)} disabled={code.length !== 6 || verifyMutation.isPending}>
                {verifyMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : null}Verify
              </Button>
              <Button variant="ghost" size="sm" onClick={() => { setStep("idle"); setCode(""); }}>Cancel</Button>
            </div>
          </CardContent>
        </Card>
      );
    }

    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="w-5 h-5 text-muted-foreground" /> Authenticator App (TOTP)
          </CardTitle>
          <CardDescription>Add an extra layer of security using TOTP-based two-factor authentication.</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <XCircle className="w-4 h-4 text-muted-foreground" />
            <Badge variant="outline" className="text-muted-foreground">Disabled</Badge>
          </div>
          <Button onClick={() => setupMutation.mutate()} disabled={setupMutation.isPending}>
            {setupMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : <Shield className="w-4 h-4 mr-1" />}
            Enable 2FA
          </Button>
        </CardContent>
      </Card>
    );
  })();

  const securityKeyList = Array.isArray(securityKeys) ? securityKeys : [];

  return (
    <div className="space-y-4">
      {totpCard}

      {/* Security Keys & Passkeys — WebAuthn (navigator.credentials) */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UsbIcon className="w-5 h-5 text-amber-400" /> Security Keys &amp; Passkeys
          </CardTitle>
          <CardDescription>
            Register hardware security keys (YubiKey, etc.) or device passkeys for phishing-resistant authentication.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {securityKeyList.length > 0 ? (
            <div className="space-y-2">
              {securityKeyList.map(key => (
                <div
                  key={key.id}
                  className="flex items-center justify-between px-3 py-2 rounded-lg border text-sm"
                  style={{ borderColor: "hsl(var(--border))", background: "hsl(var(--muted))" }}
                >
                  <div className="flex flex-col gap-0.5">
                    <span className="font-medium">{key.name}</span>
                    <span className="text-xs text-muted-foreground">
                      Registered {new Date(key.created_at).toLocaleDateString()} &middot; Last used: {daysSince(key.last_used)}
                    </span>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-red-400 hover:text-red-300 h-7 px-2"
                    disabled={removeSecurityKeyMutation.isPending}
                    onClick={() => {
                      if (window.confirm(`Remove security key "${key.name}"?`)) {
                        removeSecurityKeyMutation.mutate(key.id);
                      }
                    }}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </Button>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No security keys or passkeys registered yet.</p>
          )}

          <Button
            onClick={registerSecurityKey}
            disabled={registeringSecurityKey}
            variant="outline"
            className="w-full"
          >
            {registeringSecurityKey ? (
              <><Loader2 className="w-4 h-4 animate-spin mr-2" /> Waiting for security key…</>
            ) : (
              <><UsbIcon className="w-4 h-4 mr-2" /> Register New Security Key / Passkey</>
            )}
          </Button>

          <p className="text-xs text-muted-foreground text-center">
            Passkeys are stored in your device&apos;s secure enclave or password manager.
          </p>
        </CardContent>
      </Card>

      {/* Passkeys / WebAuthn */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Fingerprint className="w-5 h-5 text-blue-400" /> Passkeys (WebAuthn)
          </CardTitle>
          <CardDescription>
            Register biometric keys, security keys (YubiKey), or device PINs for passwordless login.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {passkeyList.length > 0 ? (
            <div className="space-y-2">
              {passkeyList.map(pk => (
                <div key={pk._id} className="flex items-center justify-between px-3 py-2 rounded-lg border text-sm"
                  style={{ borderColor: "hsl(var(--border))", background: "hsl(var(--muted))" }}>
                  <div className="flex items-center gap-2">
                    <Fingerprint className="w-4 h-4 text-blue-400" />
                    <span className="font-medium capitalize">{pk.device_type ?? "passkey"}</span>
                    {pk.transports?.length > 0 && (
                      <span className="text-xs text-muted-foreground">({pk.transports.join(", ")})</span>
                    )}
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground">
                      {new Date(pk.created_at).toLocaleDateString()}
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-red-400 hover:text-red-300 h-7 px-2"
                      onClick={() => deletePasskeyMutation.mutate(pk._id)}
                      disabled={deletePasskeyMutation.isPending}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No passkeys registered yet.</p>
          )}

          <Button
            onClick={registerPasskey}
            disabled={registeringPasskey}
            variant="outline"
            className="w-full"
          >
            {registeringPasskey ? (
              <><Loader2 className="w-4 h-4 animate-spin mr-2" /> Waiting for device…</>
            ) : (
              <><Fingerprint className="w-4 h-4 mr-2" /> Register New Passkey</>
            )}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
