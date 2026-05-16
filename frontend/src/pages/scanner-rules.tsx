import { useState, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  Code2, Plus, Trash2, Edit, Play, Download, Upload, Loader2, CheckCircle2, XCircle,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

const RULE_TYPES = ["regex_body", "regex_header", "status_code", "keyword_body", "keyword_header", "json_path"] as const;
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

type RuleType = typeof RULE_TYPES[number];
type Severity = typeof SEVERITIES[number];

interface ScannerRule {
  id: string;
  name: string;
  description?: string;
  rule_type: RuleType;
  pattern: string;
  severity: Severity;
  enabled: boolean;
  test_url?: string;
  last_tested?: string;
  match_count?: number;
  remediation?: string;
}

interface TestResult {
  matched: boolean;
  matches: string[];
  duration_ms: number;
}

const EMPTY_FORM = {
  name: "",
  description: "",
  rule_type: "regex_body" as RuleType,
  pattern: "",
  severity: "medium" as Severity,
  remediation: "",
};

function severityBadgeClass(sev: string) {
  if (sev === "critical") return "bg-red-600/20 text-red-400 border-red-500/40";
  if (sev === "high") return "bg-orange-500/20 text-orange-400 border-orange-500/40";
  if (sev === "medium") return "bg-yellow-500/20 text-yellow-400 border-yellow-500/40";
  if (sev === "low") return "bg-cyan-500/20 text-cyan-400 border-cyan-500/40";
  return "bg-slate-500/20 text-slate-400 border-slate-500/40";
}

export default function ScannerRulesPage() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const importRef = useRef<HTMLInputElement>(null);

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<ScannerRule | null>(null);
  const [form, setForm] = useState({ ...EMPTY_FORM });
  const [testUrl, setTestUrl] = useState("");
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [testing, setTesting] = useState(false);

  // Inline popover test state (per-rule)
  const [popoverRuleId, setPopoverRuleId] = useState<string | null>(null);
  const [popoverUrl, setPopoverUrl] = useState("");
  const [popoverResult, setPopoverResult] = useState<TestResult | null>(null);
  const [popoverTesting, setPopoverTesting] = useState(false);

  const { data: rules = [], isLoading } = useQuery<ScannerRule[]>({
    queryKey: ["/api/scanner-rules"],
    queryFn: () => fetch("/api/scanner-rules", { credentials: "include" }).then(r => r.json()),
  });

  const createMutation = useMutation({
    mutationFn: (data: typeof EMPTY_FORM) =>
      fetch("/api/scanner-rules", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      }).then(r => r.json()),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["/api/scanner-rules"] }); toast({ title: "Rule created" }); closeDialog(); },
    onError: () => toast({ title: "Failed to create rule", variant: "destructive" }),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<ScannerRule> }) =>
      fetch(`/api/scanner-rules/${id}`, {
        method: "PATCH", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      }).then(r => r.json()),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["/api/scanner-rules"] }); toast({ title: "Rule updated" }); closeDialog(); },
    onError: () => toast({ title: "Failed to update rule", variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/scanner-rules/${id}`, { method: "DELETE", credentials: "include" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["/api/scanner-rules"] }); toast({ title: "Rule deleted" }); },
    onError: () => toast({ title: "Failed to delete rule", variant: "destructive" }),
  });

  function openNew() {
    setEditingRule(null);
    setForm({ ...EMPTY_FORM });
    setTestUrl("");
    setTestResult(null);
    setDialogOpen(true);
  }

  function openEdit(rule: ScannerRule) {
    setEditingRule(rule);
    setForm({
      name: rule.name,
      description: rule.description ?? "",
      rule_type: rule.rule_type,
      pattern: rule.pattern,
      severity: rule.severity,
      remediation: rule.remediation ?? "",
    });
    setTestUrl(rule.test_url ?? "");
    setTestResult(null);
    setDialogOpen(true);
  }

  function closeDialog() {
    setDialogOpen(false);
    setEditingRule(null);
    setTestResult(null);
  }

  async function testRule(ruleId?: string) {
    const url = ruleId ? popoverUrl : testUrl;
    if (!url.trim()) return;
    ruleId ? setPopoverTesting(true) : setTesting(true);
    try {
      const endpoint = ruleId
        ? `/api/scanner-rules/${ruleId}/test`
        : editingRule ? `/api/scanner-rules/${editingRule.id}/test` : null;
      if (!endpoint) { toast({ title: "Save the rule first to test it", variant: "destructive" }); return; }
      const r = await fetch(endpoint, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const result: TestResult = await r.json();
      ruleId ? setPopoverResult(result) : setTestResult(result);
    } catch {
      toast({ title: "Test failed", variant: "destructive" });
    } finally {
      ruleId ? setPopoverTesting(false) : setTesting(false);
    }
  }

  function saveRule() {
    if (!form.name.trim() || !form.pattern.trim()) {
      toast({ title: "Name and pattern are required", variant: "destructive" });
      return;
    }
    if (editingRule) {
      updateMutation.mutate({ id: editingRule.id, data: form });
    } else {
      createMutation.mutate(form);
    }
  }

  function exportAll() {
    const blob = new Blob([JSON.stringify(rules, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scanner-rules-${new Date().toISOString().split("T")[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportRule(rule: ScannerRule) {
    const blob = new Blob([JSON.stringify(rule, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `rule-${rule.name.replace(/\s+/g, "-")}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function importRules(file: File) {
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const arr: Partial<ScannerRule>[] = Array.isArray(parsed) ? parsed : [parsed];
      for (const rule of arr) {
        await fetch("/api/scanner-rules", {
          method: "POST", credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(rule),
        });
      }
      qc.invalidateQueries({ queryKey: ["/api/scanner-rules"] });
      toast({ title: `Imported ${arr.length} rule(s)` });
    } catch {
      toast({ title: "Import failed — invalid JSON", variant: "destructive" });
    }
  }

  const isSaving = createMutation.isPending || updateMutation.isPending;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <Code2 className="w-6 h-6 text-violet-400" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Custom Scanner Rules</h1>
            <p className="text-sm text-muted-foreground">Write detection rules for your specific environment</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={exportAll} className="gap-1.5">
            <Download className="w-4 h-4" /> Export All
          </Button>
          <Button variant="outline" size="sm" onClick={() => importRef.current?.click()} className="gap-1.5">
            <Upload className="w-4 h-4" /> Import JSON
          </Button>
          <input
            ref={importRef} type="file" accept=".json" className="hidden"
            onChange={e => { const f = e.target.files?.[0]; if (f) importRules(f); e.target.value = ""; }}
          />
          <Button onClick={openNew} className="gap-1.5">
            <Plus className="w-4 h-4" /> New Rule
          </Button>
        </div>
      </div>

      {/* Rules table */}
      {isLoading ? (
        <div className="flex justify-center py-12 text-muted-foreground">
          <Loader2 className="w-5 h-5 animate-spin mr-2" /> Loading rules...
        </div>
      ) : rules.length === 0 ? (
        <div className="text-center py-20 text-muted-foreground">
          <Code2 className="w-12 h-12 mx-auto mb-4 opacity-30" />
          <p className="text-lg font-medium">No custom rules</p>
          <p className="text-sm mt-1">Write detection rules for your specific environment</p>
        </div>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Rules ({rules.length})</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border">
                    {["Name", "Type", "Severity", "Pattern", "Matches", "Status", "Actions"].map(col => (
                      <th key={col} className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{col}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rules.map(rule => (
                    <tr key={rule.id} className="border-b border-border last:border-0 hover:bg-muted/30 transition-colors">
                      <td className="px-4 py-3">
                        <div className="font-medium">{rule.name}</div>
                        {rule.description && <div className="text-xs text-muted-foreground truncate max-w-[180px]">{rule.description}</div>}
                      </td>
                      <td className="px-4 py-3">
                        <Badge variant="outline" className="text-xs font-mono">{rule.rule_type}</Badge>
                      </td>
                      <td className="px-4 py-3">
                        <Badge variant="outline" className={`text-xs ${severityBadgeClass(rule.severity)}`}>
                          {rule.severity}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-muted-foreground max-w-[200px] truncate" title={rule.pattern}>
                        {rule.pattern}
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {rule.match_count ?? 0}
                      </td>
                      <td className="px-4 py-3">
                        <Switch
                          checked={rule.enabled}
                          onCheckedChange={v => updateMutation.mutate({ id: rule.id, data: { enabled: v } })}
                        />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1">
                          {/* Inline test popover */}
                          <div className="relative">
                            <Button
                              size="sm" variant="outline" className="h-7 text-xs gap-1"
                              onClick={() => { setPopoverRuleId(popoverRuleId === rule.id ? null : rule.id); setPopoverUrl(""); setPopoverResult(null); }}
                            >
                              <Play className="w-3 h-3" /> Test
                            </Button>
                            {popoverRuleId === rule.id && (
                              <div className="absolute right-0 top-9 z-50 w-72 rounded-lg shadow-xl border border-border bg-card p-3 space-y-2">
                                <p className="text-xs font-semibold">Test against URL</p>
                                <Input
                                  placeholder="https://example.com/api"
                                  value={popoverUrl}
                                  onChange={e => setPopoverUrl(e.target.value)}
                                  className="h-8 text-xs"
                                />
                                <Button size="sm" className="w-full h-7 text-xs" onClick={() => testRule(rule.id)} disabled={popoverTesting || !popoverUrl.trim()}>
                                  {popoverTesting ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : <Play className="w-3 h-3 mr-1" />}
                                  Run Test
                                </Button>
                                {popoverResult && (
                                  <div className={`rounded p-2 text-xs border ${popoverResult.matched ? "bg-green-500/10 border-green-500/30 text-green-400" : "bg-muted border-border text-muted-foreground"}`}>
                                    {popoverResult.matched ? (
                                      <><CheckCircle2 className="w-3 h-3 inline mr-1" />Matched — {popoverResult.matches.length} occurrence(s) in {popoverResult.duration_ms}ms</>
                                    ) : (
                                      <><XCircle className="w-3 h-3 inline mr-1" />No match ({popoverResult.duration_ms}ms)</>
                                    )}
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                          <Button size="sm" variant="outline" className="h-7 text-xs gap-1" onClick={() => openEdit(rule)}>
                            <Edit className="w-3 h-3" /> Edit
                          </Button>
                          <Button size="sm" variant="outline" className="h-7 text-xs gap-1" onClick={() => exportRule(rule)}>
                            <Download className="w-3 h-3" />
                          </Button>
                          <Button
                            size="sm" variant="ghost" className="h-7 text-xs text-destructive hover:text-destructive hover:bg-destructive/10"
                            disabled={deleteMutation.isPending}
                            onClick={() => { if (confirm(`Delete rule "${rule.name}"?`)) deleteMutation.mutate(rule.id); }}
                          >
                            <Trash2 className="w-3 h-3" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* New/Edit Rule Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editingRule ? "Edit Rule" : "New Scanner Rule"}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label>Name *</Label>
              <Input placeholder="e.g. Detect exposed API key" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            </div>
            <div className="space-y-1.5">
              <Label>Description</Label>
              <Textarea placeholder="What does this rule detect?" rows={2} value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label>Rule Type</Label>
                <Select value={form.rule_type} onValueChange={v => setForm(f => ({ ...f, rule_type: v as RuleType }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {RULE_TYPES.map(t => <SelectItem key={t} value={t}>{t}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Severity</Label>
                <Select value={form.severity} onValueChange={v => setForm(f => ({ ...f, severity: v as Severity }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {SEVERITIES.map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label>Pattern *</Label>
              <Input
                placeholder={form.rule_type.startsWith("regex") ? "e.g. AKIA[A-Z0-9]{16}" : form.rule_type === "status_code" ? "e.g. 500" : form.rule_type === "json_path" ? "e.g. $.data.apiKey" : "e.g. apikey"}
                value={form.pattern}
                onChange={e => setForm(f => ({ ...f, pattern: e.target.value }))}
                className="font-mono text-sm"
              />
              <p className="text-xs text-muted-foreground">
                {form.rule_type.startsWith("regex") ? "Regular expression" :
                  form.rule_type === "status_code" ? "HTTP status code number" :
                  form.rule_type === "json_path" ? "JSONPath expression" : "Keyword to search for"}
              </p>
            </div>
            <div className="space-y-1.5">
              <Label>Remediation Advice</Label>
              <Textarea placeholder="Steps to remediate when this rule fires..." rows={2} value={form.remediation} onChange={e => setForm(f => ({ ...f, remediation: e.target.value }))} />
            </div>

            {/* Test Rule section (only when editing) */}
            {editingRule && (
              <div className="border border-border rounded-lg p-3 space-y-2">
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Test Rule</p>
                <div className="flex gap-2">
                  <Input
                    placeholder="https://target.com/page"
                    value={testUrl}
                    onChange={e => setTestUrl(e.target.value)}
                    className="h-8 text-sm"
                  />
                  <Button size="sm" variant="outline" onClick={() => testRule()} disabled={testing || !testUrl.trim()} className="h-8 gap-1.5 shrink-0">
                    {testing ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                    Test
                  </Button>
                </div>
                {testResult && (
                  <div className={`rounded p-2 text-xs border ${testResult.matched ? "bg-green-500/10 border-green-500/30 text-green-400" : "bg-muted border-border text-muted-foreground"}`}>
                    {testResult.matched ? (
                      <><CheckCircle2 className="w-3 h-3 inline mr-1" />Matched — {testResult.matches.length} occurrence(s) in {testResult.duration_ms}ms</>
                    ) : (
                      <><XCircle className="w-3 h-3 inline mr-1" />No match ({testResult.duration_ms}ms)</>
                    )}
                    {testResult.matches.length > 0 && (
                      <div className="mt-1 font-mono text-[10px] space-y-0.5">
                        {testResult.matches.slice(0, 3).map((m, i) => <div key={i} className="truncate">{m}</div>)}
                        {testResult.matches.length > 3 && <div>+{testResult.matches.length - 3} more</div>}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={closeDialog}>Cancel</Button>
            <Button onClick={saveRule} disabled={isSaving || !form.name.trim() || !form.pattern.trim()}>
              {isSaving ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : null}
              {editingRule ? "Save Changes" : "Create Rule"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
