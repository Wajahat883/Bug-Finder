import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ShieldCheck, X, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface AuditEntry {
  action?: string;
  username?: string;
  actor?: string;
  created_at?: string;
}

interface ChainVerifyResult {
  valid: boolean;
  count?: number;
  brokenAt?: string | number;
}

export default function AuditLog() {
  const { toast } = useToast();

  // Date range filters
  const [filterFrom, setFilterFrom] = useState("");
  const [filterTo, setFilterTo] = useState("");

  // Actor / user filter
  const [filterActor, setFilterActor] = useState("");

  // Chain integrity result
  const [chainResult, setChainResult] = useState<ChainVerifyResult | null>(null);

  // Build query params
  const buildParams = () => {
    const p = new URLSearchParams();
    if (filterFrom) p.set("from", filterFrom);
    if (filterTo) p.set("to", filterTo);
    if (filterActor) p.set("actor", filterActor);
    return p.toString();
  };

  const { data: logs = [], isLoading } = useQuery<AuditEntry[]>({
    queryKey: ["/api/audit-log", filterFrom, filterTo, filterActor],
    queryFn: () => {
      const qs = buildParams();
      return fetch(`/api/audit-log${qs ? `?${qs}` : ""}`, { credentials: "include" }).then(r => r.json());
    },
  });

  const verifyMutation = useMutation({
    mutationFn: () =>
      fetch("/api/siem/audit-chain/verify", { credentials: "include" }).then(r => r.json()),
    onSuccess: (result: ChainVerifyResult) => {
      setChainResult(result);
    },
    onError: () => {
      toast({ title: "Failed to verify chain integrity", variant: "destructive" });
    },
  });

  const clearDateRange = () => {
    setFilterFrom("");
    setFilterTo("");
  };

  const filteredLogs = (logs as AuditEntry[]).filter(log => {
    if (!filterActor) return true;
    const actor = (log.actor ?? log.username ?? "").toLowerCase();
    return actor.includes(filterActor.toLowerCase());
  });

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <h1 className="text-2xl font-bold">Audit Log</h1>
        <Button
          variant="outline"
          onClick={() => verifyMutation.mutate()}
          disabled={verifyMutation.isPending}
          className="flex items-center gap-2"
        >
          {verifyMutation.isPending ? (
            <><Loader2 className="w-4 h-4 animate-spin" /> Verifying...</>
          ) : (
            <><ShieldCheck className="w-4 h-4 text-green-400" /> Verify Chain Integrity</>
          )}
        </Button>
      </div>

      {/* Chain integrity result banner */}
      {chainResult !== null && (
        <div
          className={`rounded-lg px-4 py-3 text-sm font-medium border ${
            chainResult.valid
              ? "bg-green-500/10 text-green-400 border-green-500/20"
              : "bg-red-500/10 text-red-400 border-red-500/20"
          }`}
        >
          {chainResult.valid
            ? `✅ All ${chainResult.count ?? ""} entries verified — chain intact`
            : `🚨 Chain broken at entry ${chainResult.brokenAt ?? "unknown"} — possible tampering detected`}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-end">
        {/* Date range */}
        <div className="flex items-center gap-2">
          <div className="flex flex-col gap-1">
            <label className="text-xs text-muted-foreground">From</label>
            <Input
              type="date"
              value={filterFrom}
              onChange={e => setFilterFrom(e.target.value)}
              className="h-8 w-36 text-sm"
            />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-xs text-muted-foreground">To</label>
            <Input
              type="date"
              value={filterTo}
              onChange={e => setFilterTo(e.target.value)}
              className="h-8 w-36 text-sm"
            />
          </div>
          {(filterFrom || filterTo) && (
            <Button
              variant="ghost"
              size="sm"
              className="h-8 px-2 mt-4 text-muted-foreground hover:text-foreground"
              onClick={clearDateRange}
              title="Clear date range"
            >
              <X className="w-4 h-4" />
            </Button>
          )}
        </div>

        {/* Actor filter */}
        <div className="flex flex-col gap-1">
          <label className="text-xs text-muted-foreground">Filter by user</label>
          <Input
            type="text"
            placeholder="Username or actor..."
            value={filterActor}
            onChange={e => setFilterActor(e.target.value)}
            className="h-8 w-48 text-sm"
          />
        </div>
      </div>

      {/* Log entries */}
      {isLoading ? (
        <p className="text-muted-foreground">Loading...</p>
      ) : (
        <div className="space-y-2">
          {filteredLogs.map((log, i) => (
            <div key={i} className="border rounded p-3 text-sm">
              <span className="font-medium">{String(log.action ?? "")}</span>
              {(log.username || log.actor) && (
                <span className="ml-2 text-muted-foreground">
                  by {String(log.actor ?? log.username)}
                </span>
              )}
              {log.created_at && (
                <span className="ml-2 text-muted-foreground">
                  {new Date(String(log.created_at)).toLocaleString()}
                </span>
              )}
            </div>
          ))}
          {filteredLogs.length === 0 && (
            <p className="text-muted-foreground">No audit log entries found.</p>
          )}
        </div>
      )}
    </div>
  );
}
