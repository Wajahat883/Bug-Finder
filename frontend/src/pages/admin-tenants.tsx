import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { Building, Users2, MoreVertical, Plus, RefreshCw, Trash2 } from "lucide-react";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Tenant {
  id: string;
  name: string;
  slug: string;
  owner_email: string;
  member_count: number;
  scan_count: number;
  finding_count: number;
  created_at: string;
  active: boolean;
}

// ── 3-dot action menu ─────────────────────────────────────────────────────────

function TenantActionMenu({
  tenant,
  onToggle,
  onDelete,
}: {
  tenant: Tenant;
  onToggle: () => void;
  onDelete: () => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <Button
        variant="ghost"
        size="icon"
        className="h-7 w-7"
        onClick={() => setOpen(v => !v)}
      >
        <MoreVertical className="w-4 h-4" />
      </Button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-8 z-20 w-40 rounded-lg shadow-xl border border-border bg-card py-1">
            <button
              className="w-full text-left px-3 py-2 text-sm hover:bg-accent/50 transition-colors"
              onClick={() => { onToggle(); setOpen(false); }}
            >
              {tenant.active ? "Deactivate" : "Activate"}
            </button>
            <button
              className="w-full text-left px-3 py-2 text-sm text-red-400 hover:bg-red-500/10 transition-colors flex items-center gap-2"
              onClick={() => { onDelete(); setOpen(false); }}
            >
              <Trash2 className="w-3.5 h-3.5" /> Delete
            </button>
          </div>
        </>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AdminTenants() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [form, setForm] = useState({ name: "", owner_email: "" });

  const { data: tenants = [], isLoading, refetch } = useQuery<Tenant[]>({
    queryKey: ["/api/admin/tenants"],
    queryFn: () =>
      fetch("/api/admin/tenants", { credentials: "include" }).then(r => r.json()),
  });

  const createTenant = useMutation({
    mutationFn: (body: { name: string; owner_email: string }) =>
      fetch("/api/admin/tenants", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/admin/tenants"] });
      toast({ title: "Tenant created successfully" });
      setDialogOpen(false);
      setForm({ name: "", owner_email: "" });
    },
    onError: () => {
      toast({ title: "Failed to create tenant", variant: "destructive" });
    },
  });

  const toggleActive = useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) =>
      fetch(`/api/admin/tenants/${id}`, {
        method: "PATCH",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ active }),
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/admin/tenants"] });
      toast({ title: "Tenant status updated" });
    },
  });

  const deleteTenant = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/admin/tenants/${id}`, {
        method: "DELETE",
        credentials: "include",
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/admin/tenants"] });
      toast({ title: "Tenant deleted" });
    },
    onError: () => {
      toast({ title: "Failed to delete tenant", variant: "destructive" });
    },
  });

  // Stats
  const totalOrgs = tenants.length;
  const activeOrgs = tenants.filter(t => t.active).length;
  const totalMembers = tenants.reduce((sum, t) => sum + t.member_count, 0);
  const totalScans = tenants.reduce((sum, t) => sum + t.scan_count, 0);

  const handleCreate = () => {
    if (!form.name.trim() || !form.owner_email.trim()) return;
    createTenant.mutate(form);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-muted-foreground">
        <RefreshCw className="w-5 h-5 animate-spin mr-2" /> Loading tenants…
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <Building className="w-7 h-7" />
            Tenant Management
          </h1>
          <p className="text-muted-foreground mt-1">
            Manage organizations, owners, and tenant lifecycle.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-1.5" /> Refresh
          </Button>
          <Button size="sm" onClick={() => setDialogOpen(true)}>
            <Plus className="w-4 h-4 mr-1.5" /> New Tenant
          </Button>
        </div>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Total Orgs",    value: totalOrgs,    icon: Building },
          { label: "Active",        value: activeOrgs,   icon: Building },
          { label: "Total Members", value: totalMembers, icon: Users2 },
          { label: "Total Scans",   value: totalScans,   icon: RefreshCw },
        ].map(({ label, value, icon: Icon }) => (
          <Card key={label}>
            <CardContent className="pt-5 pb-4">
              <div className="flex items-center gap-2 mb-1">
                <Icon className="w-4 h-4 text-muted-foreground" />
                <p className="text-xs text-muted-foreground">{label}</p>
              </div>
              <p className="text-3xl font-bold">{value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Organizations</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {tenants.length === 0 ? (
            <div className="text-center py-16 text-muted-foreground text-sm">
              <Building className="w-10 h-10 mx-auto mb-3 opacity-30" />
              No tenants yet
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-xs text-muted-foreground">
                    <th className="text-left px-5 py-3 font-medium">Org Name</th>
                    <th className="text-left px-3 py-3 font-medium">Owner</th>
                    <th className="text-right px-3 py-3 font-medium">Members</th>
                    <th className="text-right px-3 py-3 font-medium">Scans</th>
                    <th className="text-right px-3 py-3 font-medium">Findings</th>
                    <th className="text-left px-3 py-3 font-medium">Created</th>
                    <th className="text-left px-3 py-3 font-medium">Status</th>
                    <th className="px-3 py-3" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {tenants.map(t => (
                    <tr key={t.id} className="hover:bg-accent/20 transition-colors">
                      <td className="px-5 py-3">
                        <div>
                          <p className="font-medium">{t.name}</p>
                          <p className="text-xs text-muted-foreground font-mono">{t.slug}</p>
                        </div>
                      </td>
                      <td className="px-3 py-3 text-muted-foreground">{t.owner_email}</td>
                      <td className="px-3 py-3 text-right font-mono">{t.member_count}</td>
                      <td className="px-3 py-3 text-right font-mono">{t.scan_count}</td>
                      <td className="px-3 py-3 text-right font-mono">{t.finding_count}</td>
                      <td className="px-3 py-3 text-muted-foreground text-xs">
                        {new Date(t.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-3 py-3">
                        <Badge
                          variant="outline"
                          className={
                            t.active
                              ? "text-green-400 border-green-400/30 bg-green-400/10 text-xs"
                              : "text-muted-foreground border-border bg-muted/20 text-xs"
                          }
                        >
                          {t.active ? "Active" : "Inactive"}
                        </Badge>
                      </td>
                      <td className="px-3 py-3">
                        <TenantActionMenu
                          tenant={t}
                          onToggle={() => toggleActive.mutate({ id: t.id, active: !t.active })}
                          onDelete={() => {
                            if (confirm(`Delete tenant "${t.name}"? This cannot be undone.`)) {
                              deleteTenant.mutate(t.id);
                            }
                          }}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* New Tenant Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create New Tenant</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="tenant-name">Organization Name *</Label>
              <Input
                id="tenant-name"
                placeholder="Acme Corp"
                value={form.name}
                onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="tenant-email">Owner Email *</Label>
              <Input
                id="tenant-email"
                type="email"
                placeholder="owner@acme.com"
                value={form.owner_email}
                onChange={e => setForm(p => ({ ...p, owner_email: e.target.value }))}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleCreate}
              disabled={!form.name.trim() || !form.owner_email.trim() || createTenant.isPending}
            >
              {createTenant.isPending ? "Creating…" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
