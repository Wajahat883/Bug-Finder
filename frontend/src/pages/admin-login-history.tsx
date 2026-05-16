import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Clock, Loader2, CheckCircle2, XCircle, X } from "lucide-react";
import { format } from "date-fns";

interface LoginEntry {
  user_email: string;
  ip: string;
  user_agent?: string;
  success: boolean;
  created_at: string;
  reason?: string;
}

function parseBrowser(ua?: string): string {
  if (!ua) return "Unknown";
  if (ua.includes("Chrome") && !ua.includes("Edg")) return "Chrome";
  if (ua.includes("Firefox")) return "Firefox";
  if (ua.includes("Safari") && !ua.includes("Chrome")) return "Safari";
  if (ua.includes("Edg")) return "Edge";
  if (ua.includes("curl")) return "curl";
  return ua.slice(0, 30);
}

function parseDevice(ua?: string): string {
  if (!ua) return "";
  if (ua.includes("Mobile") || ua.includes("Android")) return "Mobile";
  if (ua.includes("iPad") || ua.includes("Tablet")) return "Tablet";
  if (ua.includes("Windows")) return "Windows";
  if (ua.includes("Mac")) return "macOS";
  if (ua.includes("Linux")) return "Linux";
  return "";
}

export default function AdminLoginHistory() {
  const [filterUser, setFilterUser] = useState("");
  const [filterIp, setFilterIp] = useState("");
  const [filterStatus, setFilterStatus] = useState<"all" | "success" | "failed">("all");

  const { data: history = [], isLoading } = useQuery<LoginEntry[]>({
    queryKey: ["/api/admin/login-history"],
    queryFn: () =>
      fetch("/api/admin/login-history?limit=100", { credentials: "include" }).then(r => r.json()),
  });

  const filtered = history.filter(entry => {
    if (filterUser && !entry.user_email.toLowerCase().includes(filterUser.toLowerCase())) return false;
    if (filterIp && !entry.ip.includes(filterIp)) return false;
    if (filterStatus === "success" && !entry.success) return false;
    if (filterStatus === "failed" && entry.success) return false;
    return true;
  });

  const successCount = history.filter(e => e.success).length;
  const failedCount = history.filter(e => !e.success).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Clock className="w-6 h-6 text-blue-400" />
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Login History</h1>
          <p className="text-sm text-muted-foreground">Authentication events across all users</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold">{history.length}</div>
            <div className="text-xs text-muted-foreground mt-1">Total Events</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-green-400">{successCount}</div>
            <div className="text-xs text-muted-foreground mt-1">Successful</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-red-400">{failedCount}</div>
            <div className="text-xs text-muted-foreground mt-1">Failed</div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-end">
        <div className="flex flex-col gap-1">
          <label className="text-xs text-muted-foreground">Filter by user</label>
          <div className="relative">
            <Input
              placeholder="user@example.com"
              value={filterUser}
              onChange={e => setFilterUser(e.target.value)}
              className="h-8 w-56 text-sm pr-8"
            />
            {filterUser && (
              <button className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground" onClick={() => setFilterUser("")}>
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-muted-foreground">Filter by IP</label>
          <div className="relative">
            <Input
              placeholder="192.168.1.1"
              value={filterIp}
              onChange={e => setFilterIp(e.target.value)}
              className="h-8 w-40 text-sm pr-8"
            />
            {filterIp && (
              <button className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground" onClick={() => setFilterIp("")}>
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-muted-foreground">Status</label>
          <div className="flex gap-1">
            {(["all", "success", "failed"] as const).map(s => (
              <Button
                key={s}
                size="sm"
                variant={filterStatus === s ? "default" : "outline"}
                className="h-8 text-xs capitalize"
                onClick={() => setFilterStatus(s)}
              >
                {s}
              </Button>
            ))}
          </div>
        </div>
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="flex justify-center py-12 text-muted-foreground">
          <Loader2 className="w-5 h-5 animate-spin mr-2" /> Loading login history...
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-20 text-muted-foreground">
          <Clock className="w-12 h-12 mx-auto mb-4 opacity-30" />
          <p className="text-lg font-medium">No login history recorded</p>
        </div>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Events ({filtered.length})</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border">
                    {["User", "IP", "Browser / Device", "Status", "Timestamp"].map(col => (
                      <th key={col} className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{col}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((entry, i) => {
                    const browser = parseBrowser(entry.user_agent);
                    const device = parseDevice(entry.user_agent);
                    return (
                      <tr key={i} className="border-b border-border last:border-0 hover:bg-muted/30 transition-colors">
                        <td className="px-4 py-3">
                          <span className="font-mono text-xs">{entry.user_email}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-xs">{entry.ip}</span>
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground">
                          {browser}{device ? ` · ${device}` : ""}
                        </td>
                        <td className="px-4 py-3">
                          {entry.success ? (
                            <Badge variant="outline" className="text-xs bg-green-500/10 text-green-400 border-green-500/40 gap-1">
                              <CheckCircle2 className="w-3 h-3" /> Success
                            </Badge>
                          ) : (
                            <div className="flex items-center gap-1.5">
                              <Badge variant="outline" className="text-xs bg-red-500/10 text-red-400 border-red-500/40 gap-1">
                                <XCircle className="w-3 h-3" /> Failed
                              </Badge>
                              {entry.reason && (
                                <span className="text-xs text-muted-foreground" title={entry.reason}>
                                  — {entry.reason}
                                </span>
                              )}
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                          {format(new Date(entry.created_at), "MMM d, yyyy HH:mm")}
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
