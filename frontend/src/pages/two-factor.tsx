import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Shield, KeyRound, CheckCircle2, XCircle, Loader2, Copy, QrCode, RefreshCw } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export default function TwoFactorSetup() {
  const [step, setStep] = useState<"idle" | "setup" | "verify">("idle");
  const [code, setCode] = useState("");
  const [secret, setSecret] = useState("");
  const [otpauthUrl, setOtpAuthUrl] = useState("");
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: status } = useQuery<{ enabled: boolean }>({
    queryKey: ["/api/auth/2fa/status"],
    queryFn: () => fetch("/api/auth/2fa/status", { credentials: "include" }).then(r => r.json()),
    staleTime: 30000,
  });

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

  const copySecret = () => { navigator.clipboard.writeText(secret); toast({ title: "Secret copied" }); };

  if (status?.enabled) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-green-400" /> Two-Factor Authentication
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
          <KeyRound className="w-5 h-5 text-muted-foreground" /> Two-Factor Authentication
        </CardTitle>
        <CardDescription>Add an extra layer of security to your account using TOTP-based two-factor authentication.</CardDescription>
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
}
