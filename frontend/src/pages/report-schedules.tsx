import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { Clock, FileText, Mail, Calendar, Plus, Trash2, Play } from "lucide-react";
import { format } from "date-fns";

// ── Types ─────────────────────────────────────────────────────────────────

interface ReportSchedule {
  id: string;
  name: string;
  report_type: string;
  frequency: string;
  recipients: string[];
  format: string;
  next_run: string | null;
  last_run: string | null;
  enabled: boolean;
}

// ── Constants ─────────────────────────────────────────────────────────────

const REPORT_TYPES = [
  { value: "executive_summary", label: "Executive Summary" },
  { value: "compliance_report", label: "Compliance Report" },
  { value: "findings_export", label: "Findings Export" },
  { value: "risk_trend", label: "Risk Trend" },
  { value: "sla_report", label: "SLA Report" },
];

const FREQUENCIES = [
  { value: "daily", label: "Daily" },
  { value: "weekly", label: "Weekly" },
  { value: "monthly", label: "Monthly" },
];

const FORMATS = [
  { value: "pdf", label: "PDF" },
  { value: "csv", label: "CSV" },
  { value: "json", label: "JSON" },
];

// ── New Schedule Dialog ───────────────────────────────────────────────────

interface NewScheduleDialogProps {
  open: boolean;
  onClose: () => void;
  onCreate: (data: {
    name: string;
    report_type: string;
    frequency: string;
    recipients: string[];
    format: string;
  }) => void;
  isPending: boolean;
}

function NewScheduleDialog({ open, onClose, onCreate, isPending }: NewScheduleDialogProps) {
  const [name, setName] = useState("");
  const [reportType, setReportType] = useState("executive_summary");
  const [frequency, setFrequency] = useState("weekly");
  const [recipientInput, setRecipientInput] = useState("");
  const [recipients, setRecipients] = useState<string[]>([]);
  const [fmt, setFmt] = useState("pdf");

  function addRecipient() {
    const email = recipientInput.trim();
    if (email && !recipients.includes(email)) {
      setRecipients(r => [...r, email]);
      setRecipientInput("");
    }
  }

  function removeRecipient(email: string) {
    setRecipients(r => r.filter(e => e !== email));
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") { e.preventDefault(); addRecipient(); }
  }

  function handleCreate() {
    if (!name || recipients.length === 0) return;
    onCreate({ name, report_type: reportType, frequency, recipients, format: fmt });
  }

  function handleClose() {
    setName(""); setReportType("executive_summary"); setFrequency("weekly");
    setRecipients([]); setRecipientInput(""); setFmt("pdf");
    onClose();
  }

  return (
    <Dialog open={open} onOpenChange={v => { if (!v) handleClose(); }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Clock className="w-5 h-5 text-primary" />
            New Report Schedule
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div>
            <Label className="text-xs mb-1.5">Schedule Name</Label>
            <Input
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="Weekly Security Summary"
              className="h-9 text-sm"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label className="text-xs mb-1.5">Report Type</Label>
              <Select value={reportType} onValueChange={setReportType}>
                <SelectTrigger className="h-9 text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {REPORT_TYPES.map(t => (
                    <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs mb-1.5">Frequency</Label>
              <Select value={frequency} onValueChange={setFrequency}>
                <SelectTrigger className="h-9 text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {FREQUENCIES.map(f => (
                    <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div>
            <Label className="text-xs mb-1.5">Format</Label>
            <Select value={fmt} onValueChange={setFmt}>
              <SelectTrigger className="h-9 text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FORMATS.map(f => (
                  <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div>
            <Label className="text-xs mb-1.5">Recipients</Label>
            <div className="flex gap-2">
              <Input
                value={recipientInput}
                onChange={e => setRecipientInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="ciso@company.com (Enter to add)"
                className="h-9 text-sm flex-1"
                type="email"
              />
              <Button type="button" size="sm" variant="outline" onClick={addRecipient} className="h-9">
                Add
              </Button>
            </div>
            {recipients.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {recipients.map(email => (
                  <Badge key={email} variant="secondary" className="gap-1 text-xs">
                    <Mail className="w-3 h-3" />
                    {email}
                    <button onClick={() => removeRecipient(email)} className="ml-1 hover:text-destructive">×</button>
                  </Badge>
                ))}
              </div>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={handleClose} disabled={isPending}>Cancel</Button>
          <Button onClick={handleCreate} disabled={isPending || !name || recipients.length === 0}>
            <Calendar className="w-4 h-4 mr-1.5" />
            {isPending ? "Creating…" : "Create Schedule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────

export default function ReportSchedules() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const { data: schedules = [], isLoading } = useQuery<ReportSchedule[]>({
    queryKey: ["/api/report-schedules"],
    queryFn: () => fetch("/api/report-schedules", { credentials: "include" }).then(r => r.json()),
  });

  const create = useMutation({
    mutationFn: (body: object) =>
      fetch("/api/report-schedules", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/report-schedules"] });
      setDialogOpen(false);
      toast({ title: "Report schedule created" });
    },
    onError: () => toast({ title: "Failed to create schedule", variant: "destructive" }),
  });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      fetch(`/api/report-schedules/${id}`, {
        method: "PATCH", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled }),
      }).then(r => r.json()),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["/api/report-schedules"] }),
    onError: () => toast({ title: "Failed to update schedule", variant: "destructive" }),
  });

  const remove = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/report-schedules/${id}`, { method: "DELETE", credentials: "include" }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/report-schedules"] });
      toast({ title: "Schedule deleted" });
      setConfirmDelete(null);
    },
    onError: () => toast({ title: "Failed to delete schedule", variant: "destructive" }),
  });

  const runNow = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/report-schedules/${id}/send-now`, { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: (d) => toast({ title: d.ok ? "Report run triggered" : d.message ?? "Run failed" }),
    onError: () => toast({ title: "Failed to trigger run", variant: "destructive" }),
  });

  function reportTypeLabel(v: string) {
    return REPORT_TYPES.find(t => t.value === v)?.label ?? v;
  }

  function frequencyLabel(v: string) {
    return FREQUENCIES.find(f => f.value === v)?.label ?? v;
  }

  function formatLabel(v: string) {
    return FORMATS.find(f => f.value === v)?.label ?? v.toUpperCase();
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <Clock className="w-7 h-7 text-primary" />
            Scheduled Reports
          </h1>
          <p className="text-muted-foreground mt-1">
            Automate recurring security report delivery to stakeholders.
          </p>
        </div>
        <Button onClick={() => setDialogOpen(true)}>
          <Plus className="w-4 h-4 mr-1.5" />
          New Schedule
        </Button>
      </div>

      {/* Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <FileText className="w-5 h-5 text-primary" />
            Active Schedules
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="py-10 text-center text-muted-foreground text-sm">Loading…</div>
          ) : schedules.length === 0 ? (
            <div className="py-14 text-center text-muted-foreground">
              <Clock className="w-12 h-12 mx-auto mb-3 opacity-25" />
              <p className="font-semibold text-base mb-1">No report schedules</p>
              <p className="text-sm mb-4">Automate your security reporting</p>
              <Button onClick={() => setDialogOpen(true)}>
                <Plus className="w-4 h-4 mr-1.5" />
                Create Schedule
              </Button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-xs">
                    <th className="text-left pb-2 pr-4 font-semibold text-muted-foreground">Name</th>
                    <th className="text-left pb-2 pr-4 font-semibold text-muted-foreground">Report Type</th>
                    <th className="text-left pb-2 pr-4 font-semibold text-muted-foreground">Frequency</th>
                    <th className="text-left pb-2 pr-4 font-semibold text-muted-foreground">Recipients</th>
                    <th className="text-left pb-2 pr-4 font-semibold text-muted-foreground">Format</th>
                    <th className="text-left pb-2 pr-4 font-semibold text-muted-foreground">Next Run</th>
                    <th className="text-left pb-2 pr-4 font-semibold text-muted-foreground">Status</th>
                    <th className="text-left pb-2 font-semibold text-muted-foreground">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50">
                  {schedules.map(s => (
                    <tr key={s.id} className="hover:bg-accent/20 transition-colors">
                      <td className="py-3 pr-4 font-medium">{s.name}</td>
                      <td className="py-3 pr-4 text-muted-foreground">{reportTypeLabel(s.report_type)}</td>
                      <td className="py-3 pr-4">
                        <Badge variant="outline" className="text-xs capitalize">{frequencyLabel(s.frequency)}</Badge>
                      </td>
                      <td className="py-3 pr-4">
                        <div className="flex items-center gap-1">
                          <Mail className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
                          <span className="text-xs text-muted-foreground truncate max-w-[140px]">
                            {s.recipients.join(", ")}
                          </span>
                        </div>
                      </td>
                      <td className="py-3 pr-4">
                        <Badge variant="secondary" className="text-xs">{formatLabel(s.format)}</Badge>
                      </td>
                      <td className="py-3 pr-4 text-xs text-muted-foreground">
                        {s.next_run ? format(new Date(s.next_run), "MMM d, HH:mm") : "—"}
                      </td>
                      <td className="py-3 pr-4">
                        <div className="flex items-center gap-2">
                          <Switch
                            checked={s.enabled}
                            onCheckedChange={enabled => toggle.mutate({ id: s.id, enabled })}
                          />
                          <span className="text-xs text-muted-foreground">{s.enabled ? "On" : "Off"}</span>
                        </div>
                      </td>
                      <td className="py-3">
                        <div className="flex items-center gap-1.5">
                          <Button size="sm" variant="outline" className="h-7 text-xs"
                            onClick={() => runNow.mutate(s.id)}
                            disabled={runNow.isPending}
                            title="Run now">
                            <Play className="w-3 h-3" />
                          </Button>
                          {confirmDelete === s.id ? (
                            <>
                              <Button size="sm" variant="destructive" className="h-7 text-xs"
                                onClick={() => remove.mutate(s.id)}
                                disabled={remove.isPending}>
                                Confirm
                              </Button>
                              <Button size="sm" variant="ghost" className="h-7 text-xs"
                                onClick={() => setConfirmDelete(null)}>
                                Cancel
                              </Button>
                            </>
                          ) : (
                            <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                              onClick={() => setConfirmDelete(s.id)}
                              title="Delete">
                              <Trash2 className="w-3.5 h-3.5" />
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <NewScheduleDialog
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        onCreate={data => create.mutate(data)}
        isPending={create.isPending}
      />
    </div>
  );
}
