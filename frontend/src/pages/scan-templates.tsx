import { useState, useEffect, useRef } from "react";
import { useLocation } from "wouter";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Plus, Trash2, Play, Bookmark, Zap, Shield, Rocket, Edit, Download, Upload } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface Template {
  id: string;
  name: string;
  description: string;
  scan_profile: string;
  validation_enabled: boolean;
  fuzzing_enabled: boolean;
  bug_bounty_mode: boolean;
  tags: string[];
  is_builtin: boolean;
  created_at: string;
}

const PROFILE_ICONS: Record<string, React.ReactNode> = {
  quick: <Zap className="w-4 h-4 text-yellow-500" />,
  standard: <Shield className="w-4 h-4 text-blue-500" />,
  deep: <Rocket className="w-4 h-4 text-purple-500" />,
};

const profileLabel: Record<string, string> = {
  quick: "8 scanners", standard: "17 scanners", deep: "28 scanners",
};

export default function ScanTemplates() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [templates, setTemplates] = useState<Template[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const importRef = useRef<HTMLInputElement>(null);
  const [form, setForm] = useState({
    name: "", description: "", scan_profile: "standard",
    validation_enabled: true, fuzzing_enabled: false, bug_bounty_mode: false, tags: "",
  });

  const load = async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/scan-templates", { credentials: "include" });
      const data = await r.json();
      setTemplates(Array.isArray(data) ? data : []);
    } catch { }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async () => {
    try {
      const r = await fetch("/api/scan-templates", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...form,
          tags: form.tags.split(",").map(t => t.trim()).filter(Boolean),
        }),
      });
      if (!r.ok) throw new Error("Create failed");
      await load();
      setCreateOpen(false);
      setForm({ name: "", description: "", scan_profile: "standard", validation_enabled: true, fuzzing_enabled: false, bug_bounty_mode: false, tags: "" });
      toast({ title: "Template created", description: form.name });
    } catch {
      toast({ title: "Error", description: "Failed to create template", variant: "destructive" });
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Delete template "${name}"?`)) return;
    try {
      await fetch(`/api/scan-templates/${id}`, { method: "DELETE", credentials: "include" });
      await load();
      toast({ title: "Deleted", description: name });
    } catch {
      toast({ title: "Error", description: "Cannot delete", variant: "destructive" });
    }
  };

  const handleLaunch = (tmpl: Template) => {
    setLocation(`/scans/new?template=${tmpl.id}`);
  };

  const exportTemplate = (tmpl: Template) => {
    const blob = new Blob([JSON.stringify(tmpl, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `template-${tmpl.name.replace(/\s+/g, "-").toLowerCase()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const importTemplate = async (file: File) => {
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const arr: Partial<Template>[] = Array.isArray(parsed) ? parsed : [parsed];
      for (const tmpl of arr) {
        const r = await fetch("/api/scan-templates", {
          method: "POST", credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: tmpl.name, description: tmpl.description, scan_profile: tmpl.scan_profile,
            validation_enabled: tmpl.validation_enabled, fuzzing_enabled: tmpl.fuzzing_enabled,
            bug_bounty_mode: tmpl.bug_bounty_mode, tags: tmpl.tags,
          }),
        });
        if (!r.ok) throw new Error("Import failed");
      }
      await load();
      toast({ title: `Imported ${arr.length} template(s)` });
    } catch {
      toast({ title: "Import failed — invalid JSON", variant: "destructive" });
    }
  };

  if (loading) return (
    <div className="flex items-center justify-center h-64 text-muted-foreground">
      Loading templates…
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Scan Templates</h1>
          <p className="text-muted-foreground">Reusable scan configurations for repeatable security assessments</p>
        </div>
        <div className="flex gap-2">
          <input
            ref={importRef} type="file" accept=".json" className="hidden"
            onChange={e => { const f = e.target.files?.[0]; if (f) importTemplate(f); e.target.value = ""; }}
          />
          <Button variant="outline" className="gap-2" onClick={() => importRef.current?.click()}>
            <Upload className="w-4 h-4" /> Import Template
          </Button>
        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button className="gap-2"><Plus className="w-4 h-4" /> New Template</Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>Create Scan Template</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="space-y-1.5">
                <Label>Name</Label>
                <Input placeholder="My Bug Bounty Template" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
              </div>
              <div className="space-y-1.5">
                <Label>Description</Label>
                <Textarea placeholder="Describe what this template is for..." rows={2} value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
              </div>
              <div className="space-y-1.5">
                <Label>Scan Profile</Label>
                <Select value={form.scan_profile} onValueChange={v => setForm(f => ({ ...f, scan_profile: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="quick">Quick — 8 scanners (~2 min)</SelectItem>
                    <SelectItem value="standard">Standard — 17 scanners (~8 min)</SelectItem>
                    <SelectItem value="deep">Deep — 28 scanners (~20 min)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-3">
                {[
                  { key: "validation_enabled", label: "Vulnerability Validation" },
                  { key: "fuzzing_enabled", label: "Active Fuzzing" },
                  { key: "bug_bounty_mode", label: "Bug Bounty Mode" },
                ].map(({ key, label }) => (
                  <div key={key} className="flex items-center justify-between">
                    <Label>{label}</Label>
                    <Switch checked={form[key as keyof typeof form] as boolean} onCheckedChange={v => setForm(f => ({ ...f, [key]: v }))} />
                  </div>
                ))}
              </div>
              <div className="space-y-1.5">
                <Label>Tags (comma-separated)</Label>
                <Input placeholder="api, bounty, owasp" value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))} />
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
              <Button onClick={handleCreate} disabled={!form.name}>Create Template</Button>
            </div>
          </DialogContent>
        </Dialog>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {templates.map(tmpl => (
          <Card key={tmpl.id} className="flex flex-col">
            <CardHeader>
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Bookmark className="w-5 h-5 text-primary shrink-0" />
                  <CardTitle className="text-base">{tmpl.name}</CardTitle>
                </div>
                {tmpl.is_builtin && <Badge variant="outline" className="text-xs shrink-0">Built-in</Badge>}
              </div>
              <CardDescription className="mt-1 line-clamp-2">{tmpl.description || "No description"}</CardDescription>
            </CardHeader>
            <CardContent className="flex-1 space-y-4">
              <div className="flex items-center gap-2 text-sm">
                {PROFILE_ICONS[tmpl.scan_profile]}
                <span className="capitalize font-medium">{tmpl.scan_profile}</span>
                <span className="text-muted-foreground">— {profileLabel[tmpl.scan_profile]}</span>
              </div>
              <div className="flex flex-wrap gap-1">
                {tmpl.validation_enabled && <Badge variant="secondary" className="text-xs">Validation</Badge>}
                {tmpl.fuzzing_enabled && <Badge variant="secondary" className="text-xs">Fuzzing</Badge>}
                {tmpl.bug_bounty_mode && <Badge variant="secondary" className="text-xs">Bug Bounty</Badge>}
                {tmpl.tags?.map(tag => (
                  <Badge key={tag} variant="outline" className="text-xs">{tag}</Badge>
                ))}
              </div>
            </CardContent>
            <div className="px-6 pb-4 flex gap-2">
              <Button size="sm" className="flex-1 gap-2" onClick={() => handleLaunch(tmpl)}>
                <Play className="w-3 h-3" /> Use Template
              </Button>
              <Button size="sm" variant="outline" className="gap-1" onClick={() => exportTemplate(tmpl)} title="Export template">
                <Download className="w-3.5 h-3.5" />
              </Button>
              {!tmpl.is_builtin && (
                <Button size="sm" variant="ghost" className="text-destructive hover:text-destructive" onClick={() => handleDelete(tmpl.id, tmpl.name)}>
                  <Trash2 className="w-4 h-4" />
                </Button>
              )}
            </div>
          </Card>
        ))}
      </div>
      {templates.length === 0 && (
        <div className="text-center py-20 text-muted-foreground">
          <Bookmark className="w-10 h-10 mx-auto mb-4 opacity-50" />
          <p>No templates found</p>
        </div>
      )}
    </div>
  );
}
