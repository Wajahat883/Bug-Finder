import { useState } from "react";
import { useListScanJobs, useDeleteScanJob } from "@workspace/api-client-react";
import { Link, useLocation } from "wouter";
import { 
  Card, CardContent, CardHeader, CardTitle, CardDescription 
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Search, Plus, Trash2, MoreHorizontal, Eye, ShieldAlert } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { format } from "date-fns";

export default function Scans() {
  const [, setLocation] = useLocation();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  
  const { data: scansResponse, isLoading } = useListScanJobs({
    search: search || undefined,
    status: statusFilter !== "all" ? statusFilter as any : undefined,
  });

  const deleteScan = useDeleteScanJob({
    mutation: {
      onSuccess: () => {
        // Optimistic update or refetch can be added here
      }
    }
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Scan Jobs</h1>
          <p className="text-muted-foreground">Manage and monitor vulnerability assessments.</p>
        </div>
        <Button onClick={() => setLocation('/scans/new')}>
          <Plus className="w-4 h-4 mr-2" />
          New Scan
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 w-full max-w-sm">
              <div className="relative flex-1">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search targets..."
                  className="pl-8"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-[180px]">
                  <SelectValue placeholder="Filter by status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Statuses</SelectItem>
                  <SelectItem value="queued">Queued</SelectItem>
                  <SelectItem value="running">Running</SelectItem>
                  <SelectItem value="completed">Completed</SelectItem>
                  <SelectItem value="failed">Failed</SelectItem>
                  <SelectItem value="cancelled">Cancelled</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border border-border">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-muted-foreground uppercase bg-muted/50 border-b border-border">
                <tr>
                  <th className="px-4 py-3">Target</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Profile</th>
                  <th className="px-4 py-3">Progress</th>
                  <th className="px-4 py-3">Findings</th>
                  <th className="px-4 py-3">Created At</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {isLoading ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">
                      Loading scans...
                    </td>
                  </tr>
                ) : scansResponse?.items.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">
                      No scans found matching your criteria.
                    </td>
                  </tr>
                ) : (
                  scansResponse?.items.map((scan) => (
                    <tr key={scan.id} className="hover:bg-muted/20">
                      <td className="px-4 py-3 font-mono text-sm">
                        <Link href={`/scans/${scan.id}`} className="hover:underline font-medium text-primary">
                          {scan.target_url}
                        </Link>
                      </td>
                      <td className="px-4 py-3">
                        <Badge variant="outline" className={`capitalize ${
                          scan.status === 'running' ? 'bg-blue-500/10 text-blue-500 border-blue-500/20' :
                          scan.status === 'completed' ? 'bg-green-500/10 text-green-500 border-green-500/20' :
                          scan.status === 'failed' ? 'bg-destructive/10 text-destructive border-destructive/20' :
                          'bg-muted text-muted-foreground border-border'
                        }`}>
                          {scan.status}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-xs uppercase tracking-wider text-muted-foreground font-semibold">
                        {scan.scan_profile}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-full bg-secondary rounded-full h-1.5">
                            <div 
                              className="bg-primary h-1.5 rounded-full" 
                              style={{ width: `${scan.progress}%` }}
                            ></div>
                          </div>
                          <span className="text-xs text-muted-foreground">{scan.progress}%</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        {scan.status === 'completed' ? (
                          <div className="flex items-center gap-1.5">
                            <ShieldAlert className="w-4 h-4 text-muted-foreground" />
                            <span className="font-medium">{scan.findings_count}</span>
                          </div>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-muted-foreground text-xs whitespace-nowrap">
                        {format(new Date(scan.created_at), "MMM d, yyyy HH:mm")}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" className="h-8 w-8 p-0">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => setLocation(`/scans/${scan.id}`)}>
                              <Eye className="mr-2 h-4 w-4" />
                              View Details
                            </DropdownMenuItem>
                            <DropdownMenuItem 
                              className="text-destructive focus:text-destructive"
                              onClick={() => {
                                if (confirm("Are you sure you want to delete this scan?")) {
                                  deleteScan.mutate({ id: scan.id });
                                }
                              }}
                            >
                              <Trash2 className="mr-2 h-4 w-4" />
                              Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
