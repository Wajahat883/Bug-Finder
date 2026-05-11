import { useQuery } from "@tanstack/react-query";

export default function AuditLog() {
  const { data: logs = [], isLoading } = useQuery({
    queryKey: ["/api/audit-log"],
    queryFn: () => fetch("/api/audit-log", { credentials: "include" }).then((r) => r.json()),
  });

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Audit Log</h1>
      {isLoading ? (
        <p className="text-muted-foreground">Loading...</p>
      ) : (
        <div className="space-y-2">
          {(logs as Array<Record<string, unknown>>).map((log, i) => (
            <div key={i} className="border rounded p-3 text-sm">
              <span className="font-medium">{String(log.action)}</span>
              {log.username && <span className="ml-2 text-muted-foreground">by {String(log.username)}</span>}
              {log.created_at && <span className="ml-2 text-muted-foreground">{new Date(String(log.created_at)).toLocaleString()}</span>}
            </div>
          ))}
          {logs.length === 0 && <p className="text-muted-foreground">No audit log entries yet.</p>}
        </div>
      )}
    </div>
  );
}
