import { useState } from "react";
import { Link } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  ShieldAlert, KeyRound, Loader2, ExternalLink, RotateCcw, CheckCircle2,
} from "lucide-react";
import { format } from "date-fns";
import { useToast } from "@/hooks/use-toast";

interface Secret {
  id: string;
  title: string;
  severity: string;
  target_url: string;
  endpoint: string;
  secret_type?: string;
  secret_value?: string;
  confidence?: string;
  status: string;
  created_at: string;
  category?: string;
}

// Detect secret type from title/category
function detectSecretType(secret: Secret): { label: string; className: string } {
  const t = (secret.title + " " + (secret.category ?? "")).toLowerCase();
  if (t.includes("aws_access_key") || t.includes("aws")) {
    return { label: "AWS Key", className: "bg-orange-500/20 text-orange-400 border-orange-500/40" };
  }
  if (t.includes("github")) {
    return { label: "GitHub Token", className: "bg-purple-500/20 text-purple-400 border-purple-500/40" };
  }
  if (t.includes("jwt")) {
    return { label: "JWT Token", className: "bg-blue-500/20 text-blue-400 border-blue-500/40" };
  }
  if (t.includes("password")) {
    return { label: "Password", className: "bg-red-500/20 text-red-400 border-red-500/40" };
  }
  return { label: "Generic Secret", className: "bg-muted text-muted-foreground border-border" };
}

function confidenceBadge(confidence?: string) {
  if (confidence === "high") return "bg-green-500/20 text-green-400 border-green-500/40";
  if (confidence === "medium") return "bg-yellow-500/20 text-yellow-400 border-yellow-500/40";
  return "bg-muted text-muted-foreground border-border";
}

function severityColor(severity: string) {
  const s = severity.toLowerCase();
  if (s === "critical") return "bg-red-600 text-white";
  if (s === "high") return "bg-orange-500 text-white";
  if (s === "medium") return "bg-yellow-500 text-black";
  if (s === "low") return "bg-cyan-500 text-black";
  return "bg-slate-500 text-white";
}

const SECRET_TYPES = ["All", "AWS Key", "GitHub Token", "JWT Token", "Password", "Generic Secret"];
const CONFIDENCE_LEVELS = ["All", "high", "medium", "low"];
const STATUSES = ["All", "open", "resolved", "false_positive"];

export default function SecretsPage() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [typeFilter, setTypeFilter] = useState("All");
  const [confidenceFilter, setConfidenceFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");

  // Fetch secrets findings
  const { data: secretsData, isLoading: l1 } = useQuery<{ findings?: Secret[] }>({
    queryKey: ["/api/findings", "secrets"],
    queryFn: () =>
      fetch("/api/findings?category=secrets&category=js_secrets&page_size=100", { credentials: "include" }).then(r => r.json()),
  });

  const { data: exposureData, isLoading: l2 } = useQuery<{ findings?: Secret[] }>({
    queryKey: ["/api/findings", "secret_exposure"],
    queryFn: () =>
      fetch("/api/findings?category=secret_exposure&page_size=100", { credentials: "include" }).then(r => r.json()),
  });

  const isLoading = l1 || l2;

  const allSecrets: Secret[] = [
    ...(secretsData?.findings ?? []),
    ...(exposureData?.findings ?? []),
  ];

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, string> }) =>
      fetch(`/api/findings/${id}`, {
        method: "PATCH", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/findings", "secrets"] });
      qc.invalidateQueries({ queryKey: ["/api/findings", "secret_exposure"] });
      toast({ title: "Finding updated" });
    },
    onError: () => toast({ title: "Update failed", variant: "destructive" }),
  });

  // Apply filters
  const filtered = allSecrets.filter(s => {
    const detected = detectSecretType(s);
    if (typeFilter !== "All" && detected.label !== typeFilter) return false;
    if (confidenceFilter !== "All" && (s.confidence ?? "low") !== confidenceFilter) return false;
    if (statusFilter !== "All" && s.status !== statusFilter) return false;
    return true;
  });

  // Stats
  const total = allSecrets.length;
  const awsKeys = allSecrets.filter(s => detectSecretType(s).label === "AWS Key").length;
  const githubTokens = allSecrets.filter(s => detectSecretType(s).label === "GitHub Token").length;
  const passwords = allSecrets.filter(s => detectSecretType(s).label === "Password").length;
  const rotated = allSecrets.filter(s => s.status === "resolved").length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-6 h-6 text-red-400" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Exposed Secrets</h1>
            <p className="text-sm text-muted-foreground">Secrets and credentials detected by the JS Secrets scanner</p>
          </div>
        </div>
        <Link href="/scans/new">
          <Button className="gap-2">
            <KeyRound className="w-4 h-4" /> Scan for Secrets
          </Button>
        </Link>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: "Total Exposed", value: total, className: "text-red-400" },
          { label: "AWS Keys", value: awsKeys, className: "text-orange-400" },
          { label: "GitHub Tokens", value: githubTokens, className: "text-purple-400" },
          { label: "Generic Passwords", value: passwords, className: "text-red-400" },
          { label: "Rotated", value: rotated, className: "text-green-400" },
        ].map(stat => (
          <Card key={stat.label}>
            <CardContent className="p-4 text-center">
              <div className={`text-2xl font-bold ${stat.className}`}>{stat.value}</div>
              <div className="text-xs text-muted-foreground mt-1">{stat.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap gap-3">
        <div className="flex flex-col gap-1">
          <label className="text-xs text-muted-foreground">Secret Type</label>
          <select
            className="h-8 px-2 text-sm rounded border border-border bg-background"
            value={typeFilter}
            onChange={e => setTypeFilter(e.target.value)}
          >
            {SECRET_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-muted-foreground">Confidence</label>
          <select
            className="h-8 px-2 text-sm rounded border border-border bg-background"
            value={confidenceFilter}
            onChange={e => setConfidenceFilter(e.target.value)}
          >
            {CONFIDENCE_LEVELS.map(c => <option key={c} value={c}>{c === "All" ? "All" : c.charAt(0).toUpperCase() + c.slice(1)}</option>)}
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-muted-foreground">Status</label>
          <select
            className="h-8 px-2 text-sm rounded border border-border bg-background"
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
          >
            {STATUSES.map(s => <option key={s} value={s}>{s === "All" ? "All" : s.replace("_", " ")}</option>)}
          </select>
        </div>
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="flex justify-center py-12 text-muted-foreground">
          <Loader2 className="w-5 h-5 animate-spin mr-2" /> Loading secrets...
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-20 text-muted-foreground">
          <KeyRound className="w-12 h-12 mx-auto mb-4 opacity-30" />
          <p className="text-lg font-medium">No exposed secrets found</p>
          <p className="text-sm mt-1">Run a scan with JS Secrets engine enabled</p>
        </div>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Exposed Secrets ({filtered.length})</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border">
                    {["Secret Type", "Location", "Confidence", "Severity", "Status", "Discovered", "Actions"].map(col => (
                      <th key={col} className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{col}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(secret => {
                    const secretType = detectSecretType(secret);
                    return (
                      <tr key={secret.id} className="border-b border-border last:border-0 hover:bg-muted/30 transition-colors">
                        <td className="px-4 py-3">
                          <Badge variant="outline" className={`text-xs ${secretType.className}`}>
                            {secretType.label}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 max-w-xs">
                          <div className="text-xs font-mono truncate text-muted-foreground" title={secret.endpoint}>
                            {secret.endpoint}
                          </div>
                          <div className="text-xs text-muted-foreground/60 truncate" title={secret.target_url}>
                            {secret.target_url}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <Badge variant="outline" className={`text-xs ${confidenceBadge(secret.confidence)}`}>
                            {secret.confidence ?? "low"}
                          </Badge>
                        </td>
                        <td className="px-4 py-3">
                          <Badge className={`text-xs uppercase border-none ${severityColor(secret.severity)}`}>
                            {secret.severity}
                          </Badge>
                        </td>
                        <td className="px-4 py-3">
                          <Badge variant="outline" className={`text-xs ${
                            secret.status === "resolved" ? "text-green-400 border-green-500/40" :
                            secret.status === "false_positive" ? "text-yellow-400 border-yellow-500/40" :
                            "text-muted-foreground"
                          }`}>
                            {secret.status.replace("_", " ")}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                          {format(new Date(secret.created_at), "MMM d, yyyy")}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1">
                            {secret.status !== "resolved" && (
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 text-xs border-green-500/40 text-green-400 hover:bg-green-500/10 gap-1"
                                disabled={updateMutation.isPending}
                                onClick={() => updateMutation.mutate({ id: secret.id, data: { status: "resolved", resolution_note: "Secret rotated" } })}
                              >
                                <RotateCcw className="w-3 h-3" /> Rotated
                              </Button>
                            )}
                            {secret.status !== "false_positive" && (
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 text-xs border-yellow-500/40 text-yellow-400 hover:bg-yellow-500/10 gap-1"
                                disabled={updateMutation.isPending}
                                onClick={() => updateMutation.mutate({ id: secret.id, data: { status: "false_positive" } })}
                              >
                                <CheckCircle2 className="w-3 h-3" /> Accept Risk
                              </Button>
                            )}
                            <Link href={`/findings/${secret.id}`}>
                              <Button size="sm" variant="ghost" className="h-7 text-xs gap-1">
                                <ExternalLink className="w-3 h-3" /> View
                              </Button>
                            </Link>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
