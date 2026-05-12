import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Clock, Plus, Trash2, Loader2, Play, Pause, Timer } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

const CRON_PRESETS = [
  { label: "Every 30 minutes", value: "*/30 * * * *" },
  { label: "Every hour", value: "0 * * * *" },
  { label: "Every 6 hours", value: "0 */6 * * *" },
  { label: "Daily at midnight", value: "0 0 * * *" },
  { label: "Daily at 9 AM", value: "0 9 * * *" },
  { label: "Weekly (Monday 8 AM)", value: "0 8 * * 1" },
];

export default function ScheduledScans() {
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ target_url: "", scan_profile: "standard", cron_expression: "0 0 * * *" });
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: schedules = [], isLoading } = useQuery<Array<Record<string, unknown>>>({
    queryKey: ["/api/scheduled-scans"],
    queryFn: () => fetch("/api/scheduled-scans", { credentials: "include" }).then(r => r.json()),
    staleTime: 15000,
  });

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => fetch("/api/scheduled-scans", { method: "POST", credentials: "include", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) }).then(r => r.json()),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["/api/scheduled-scans"] }); setShowForm(false); toast({ title: "Scheduled scan created" }); },
    onError: () => toast({ title: "Failed to create", variant: "destructive" }),
  });

  const toggleMutation = useMutation({
    mutationFn: (vars: { id: string; enabled: boolean }) => fetch(`/api/scheduled-scans/${vars.id}`, { method: "PATCH", credentials: "include", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: vars.enabled }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["/api/scheduled-scans"] }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => fetch(`/api/scheduled-scans/${id}`, { method: "DELETE", credentials: "include" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["/api/scheduled-scans"] }); toast({ title: "Schedule removed" }); },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <Clock className="w-7 h-7 text-purple-400" /> Scheduled Scans
          </h1>
          <p className="text-muted-foreground mt-1">Automate recurring security scans with cron schedules.</p>
        </div>
        <Button onClick={() => setShowForm(!showForm)} className="gap-2">
          <Plus className="w-4 h-4" /> New Schedule
        </Button>
      </div>

      {showForm && (
        <Card>
          <CardContent className="p-5 space-y-4">
            <div>
              <label className="text-sm font-medium mb-1 block">Target URL</label>
              <Input placeholder="https://api.target.com" value={form.target_url} onChange={e => setForm(p => ({ ...p, target_url: e.target.value }))} />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium mb-1 block">Scan Profile</label>
                <Select value={form.scan_profile} onValueChange={v => setForm(p => ({ ...p, scan_profile: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="quick">Quick (~15 modules)</SelectItem>
                    <SelectItem value="standard">Standard (~30 modules)</SelectItem>
                    <SelectItem value="deep">Deep (~60 modules)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-sm font-medium mb-1 block">Schedule</label>
                <Select value={form.cron_expression} onValueChange={v => setForm(p => ({ ...p, cron_expression: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {CRON_PRESETS.map(p => <SelectItem key={p.value} value={p.value}>{p.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" onClick={() => setShowForm(false)}>Cancel</Button>
              <Button onClick={() => createMutation.mutate(form)} disabled={!form.target_url || createMutation.isPending}>
                {createMutation.isPending ? <><Loader2 className="w-4 h-4 animate-spin mr-1" />Creating...</> : "Create Schedule"}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-8 text-center text-muted-foreground"><Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />Loading schedules...</div>
          ) : schedules.length === 0 ? (
            <div className="p-12 text-center text-muted-foreground">
              <Timer className="w-12 h-12 mx-auto mb-3 opacity-30" />
              <p className="text-lg font-medium mb-1">No scheduled scans</p>
              <p className="text-sm">Create a recurring scan schedule to automate your security testing.</p>
            </div>
          ) : (
            <div className="divide-y divide-border">
              {schedules.map((s: Record<string, unknown>) => (
                <div key={String(s.id)} className="flex items-center justify-between p-4 hover:bg-muted/20 transition-colors">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-semibold font-mono text-sm">{String(s.target_url)}</span>
                      <Badge variant="outline" className="text-[10px]">{String(s.scan_profile)}</Badge>
                      {s.enabled ? <Badge className="bg-green-500/10 text-green-400 border-green-500/20 text-[10px]">Active</Badge> : <Badge variant="outline" className="text-[10px] text-muted-foreground">Paused</Badge>}
                    </div>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{String(s.cron_description ?? s.cron_expression)}</span>
                      {s.last_run && <span>Last run: {new Date(s.last_run as string).toLocaleDateString()}</span>}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 ml-4">
                    <Switch checked={!!s.enabled} onCheckedChange={v => toggleMutation.mutate({ id: String(s.id), enabled: v })} />
                    <Button variant="ghost" size="sm" className="text-red-400 hover:bg-red-500/10 h-8 w-8 p-0" onClick={() => { if (confirm("Remove this schedule?")) deleteMutation.mutate(String(s.id)); }}>
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
