import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Lock, Save, Loader2, Shield } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface Policy {
  enforce_2fa: boolean;
  session_timeout_minutes: number;
  data_retention_days: number;
  max_failed_logins: number;
  password_min_length: number;
}

export default function AdminPolicy() {
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: policy, isLoading } = useQuery<Policy>({
    queryKey: ["/api/admin/policy"],
    queryFn: () => fetch("/api/admin/policy", { credentials: "include" }).then(r => r.json()),
  });

  const [form, setForm] = useState<Policy>({
    enforce_2fa: false,
    session_timeout_minutes: 480,
    data_retention_days: 365,
    max_failed_logins: 5,
    password_min_length: 12,
  });

  useEffect(() => { if (policy) setForm(policy); }, [policy]);

  const saveMutation = useMutation({
    mutationFn: () => fetch("/api/admin/policy", {
      method: "PATCH", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(form),
    }).then(r => r.json()),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["/api/admin/policy"] }); toast({ title: "Policy saved" }); },
    onError: () => toast({ title: "Failed to save policy", variant: "destructive" }),
  });

  const num = (key: keyof Policy, min: number, max: number) => (
    <Input
      type="number"
      min={min}
      max={max}
      value={form[key] as number}
      onChange={e => setForm(f => ({ ...f, [key]: parseInt(e.target.value) || min }))}
      className="w-32 font-mono"
    />
  );

  if (isLoading) {
    return <div className="flex justify-center py-12"><Loader2 className="w-6 h-6 animate-spin text-muted-foreground" /></div>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Lock className="w-6 h-6 text-orange-400" /> Platform Policy
        </h1>
        <p className="text-muted-foreground mt-1 text-sm">
          Configure global security policies enforced across all users.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Shield className="w-4 h-4 text-purple-400" /> Authentication Policy
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="flex items-center justify-between py-2 border-b" style={{ borderColor: "hsl(var(--border))" }}>
            <div>
              <p className="text-sm font-medium">Enforce Two-Factor Authentication</p>
              <p className="text-xs text-muted-foreground mt-0.5">Require all users to have 2FA enabled before accessing the platform.</p>
            </div>
            <button
              onClick={() => setForm(f => ({ ...f, enforce_2fa: !f.enforce_2fa }))}
              className="relative w-11 h-6 rounded-full transition-colors flex-shrink-0"
              style={{ background: form.enforce_2fa ? "#7c3aed" : "hsl(var(--muted))" }}
            >
              <span className="absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform"
                style={{ transform: form.enforce_2fa ? "translateX(20px)" : "translateX(0)" }} />
            </button>
          </div>

          <div className="flex items-center justify-between py-2 border-b" style={{ borderColor: "hsl(var(--border))" }}>
            <div>
              <p className="text-sm font-medium">Maximum Failed Login Attempts</p>
              <p className="text-xs text-muted-foreground mt-0.5">Lock account after this many consecutive failed login attempts.</p>
            </div>
            {num("max_failed_logins", 3, 20)}
          </div>

          <div className="flex items-center justify-between py-2">
            <div>
              <p className="text-sm font-medium">Minimum Password Length</p>
              <p className="text-xs text-muted-foreground mt-0.5">Passwords must be at least this many characters.</p>
            </div>
            {num("password_min_length", 8, 32)}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Session & Data Policy</CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="flex items-center justify-between py-2 border-b" style={{ borderColor: "hsl(var(--border))" }}>
            <div>
              <p className="text-sm font-medium">Session Timeout (minutes)</p>
              <p className="text-xs text-muted-foreground mt-0.5">Automatically expire idle sessions after this many minutes.</p>
            </div>
            {num("session_timeout_minutes", 15, 1440)}
          </div>

          <div className="flex items-center justify-between py-2">
            <div>
              <p className="text-sm font-medium">Data Retention (days)</p>
              <p className="text-xs text-muted-foreground mt-0.5">Automatically purge scan data and findings older than this many days.</p>
            </div>
            <div className="flex items-center gap-2">
              {num("data_retention_days", 30, 3650)}
              {form.data_retention_days < 90 && (
                <Badge className="text-[10px] bg-yellow-500/10 text-yellow-400 border-yellow-500/20">Short</Badge>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
          {saveMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Save className="w-4 h-4 mr-2" />}
          Save Policy
        </Button>
      </div>
    </div>
  );
}
