import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { format } from "date-fns";
import { Shield, UserCog, UserX, UserCheck, Search, RefreshCw } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  is_active: boolean;
  created_at: string;
  last_login?: string;
}

const ROLE_COLORS: Record<string, string> = {
  admin: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  analyst: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  viewer: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

export default function AdminUsers() {
  const [search, setSearch] = useState("");
  const [editUser, setEditUser] = useState<User | null>(null);
  const [editRole, setEditRole] = useState("");
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data, isLoading, refetch } = useQuery<User[]>({
    queryKey: ["/api/admin/users"],
    queryFn: () =>
      fetch("/api/admin/users", { credentials: "include" }).then(r => {
        if (!r.ok) throw new Error("Unauthorized");
        return r.json();
      }),
    staleTime: 30000,
  });

  const users: User[] = data ?? [];
  const filtered = users.filter(u =>
    !search ||
    u.email.toLowerCase().includes(search.toLowerCase()) ||
    u.name?.toLowerCase().includes(search.toLowerCase())
  );

  const updateUser = useMutation({
    mutationFn: (vars: { id: string; role?: string; is_active?: boolean }) =>
      fetch(`/api/admin/users/${vars.id}`, {
        method: "PATCH",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role: vars.role, is_active: vars.is_active }),
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/admin/users"] });
      toast({ title: "User updated" });
      setEditUser(null);
    },
    onError: () => toast({ title: "Failed to update user", variant: "destructive" }),
  });

  const deleteUser = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/admin/users/${id}`, { method: "DELETE", credentials: "include" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/admin/users"] });
      toast({ title: "User removed" });
    },
    onError: () => toast({ title: "Failed to remove user", variant: "destructive" }),
  });

  function openEdit(user: User) {
    setEditUser(user);
    setEditRole(user.role);
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <Shield className="w-7 h-7 text-purple-400" />
            User Management
          </h1>
          <p className="text-muted-foreground mt-1">Manage platform access, roles, and account status.</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="w-4 h-4 mr-1.5" />Refresh
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <input
                className="w-full pl-8 pr-3 py-2 text-sm bg-transparent border border-border rounded-md outline-none placeholder:text-muted-foreground"
                placeholder="Search by email or name..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <span className="text-sm text-muted-foreground">{filtered.length} user{filtered.length !== 1 ? "s" : ""}</span>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead className="text-xs text-muted-foreground uppercase bg-muted/50 border-b border-border">
                <tr>
                  <th className="px-4 py-3 text-left">User</th>
                  <th className="px-4 py-3 text-left">Role</th>
                  <th className="px-4 py-3 text-left">Status</th>
                  <th className="px-4 py-3 text-left">Joined</th>
                  <th className="px-4 py-3 text-left">Last Login</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {isLoading ? (
                  <tr><td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">Loading users…</td></tr>
                ) : filtered.length === 0 ? (
                  <tr><td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">No users found.</td></tr>
                ) : (
                  filtered.map((user) => (
                    <tr key={user.id} className="hover:bg-muted/20">
                      <td className="px-4 py-3">
                        <div className="font-medium">{user.name || "—"}</div>
                        <div className="text-xs text-muted-foreground font-mono">{user.email}</div>
                      </td>
                      <td className="px-4 py-3">
                        <Badge variant="outline" className={`text-[10px] uppercase font-bold ${ROLE_COLORS[user.role] ?? ""}`}>
                          {user.role}
                        </Badge>
                      </td>
                      <td className="px-4 py-3">
                        {user.is_active ? (
                          <span className="flex items-center gap-1.5 text-green-400 text-xs">
                            <span className="w-1.5 h-1.5 rounded-full bg-green-400" />Active
                          </span>
                        ) : (
                          <span className="flex items-center gap-1.5 text-muted-foreground text-xs">
                            <span className="w-1.5 h-1.5 rounded-full bg-muted-foreground" />Inactive
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {format(new Date(user.created_at), "MMM d, yyyy")}
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {user.last_login ? format(new Date(user.last_login), "MMM d, yyyy HH:mm") : "Never"}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={() => openEdit(user)}>
                            <UserCog className="w-3.5 h-3.5 mr-1" />Edit
                          </Button>
                          <Button
                            variant="ghost" size="sm"
                            className={`h-7 px-2 text-xs ${user.is_active ? "text-orange-400 hover:text-orange-300" : "text-green-400 hover:text-green-300"}`}
                            onClick={() => updateUser.mutate({ id: user.id, is_active: !user.is_active })}
                          >
                            {user.is_active
                              ? <><UserX className="w-3.5 h-3.5 mr-1" />Deactivate</>
                              : <><UserCheck className="w-3.5 h-3.5 mr-1" />Activate</>
                            }
                          </Button>
                          <Button
                            variant="ghost" size="sm"
                            className="h-7 px-2 text-xs text-destructive hover:text-destructive"
                            onClick={() => {
                              if (confirm(`Remove user ${user.email}?`)) deleteUser.mutate(user.id);
                            }}
                          >
                            Remove
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Edit Role Dialog */}
      <Dialog open={!!editUser} onOpenChange={(o) => !o && setEditUser(null)}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle>Edit User Role</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <p className="text-sm text-muted-foreground">User</p>
              <p className="font-medium">{editUser?.email}</p>
            </div>
            <div>
              <label className="text-sm font-medium mb-1.5 block">Role</label>
              <Select value={editRole} onValueChange={setEditRole}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="admin">Admin — Full access</SelectItem>
                  <SelectItem value="analyst">Analyst — Run scans &amp; manage findings</SelectItem>
                  <SelectItem value="viewer">Viewer — Read-only access</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditUser(null)}>Cancel</Button>
            <Button
              disabled={updateUser.isPending}
              onClick={() => editUser && updateUser.mutate({ id: editUser.id, role: editRole })}
            >
              {updateUser.isPending ? "Saving…" : "Save Changes"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
