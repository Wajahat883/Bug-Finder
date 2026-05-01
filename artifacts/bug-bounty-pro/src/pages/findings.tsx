import { useState } from "react";
import { Link, useLocation } from "wouter";
import { useListFindings } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Search, Filter } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { format } from "date-fns";

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-[hsl(var(--critical))] text-white",
    high: "bg-[hsl(var(--high))] text-white",
    medium: "bg-[hsl(var(--medium))] text-black",
    low: "bg-[hsl(var(--low))] text-black",
    info: "bg-[hsl(var(--info))] text-white",
  };
  
  return (
    <Badge className={`${colors[severity.toLowerCase()]} border-none uppercase text-[10px]`}>
      {severity}
    </Badge>
  );
}

export default function Findings() {
  const [, setLocation] = useLocation();
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  
  const { data: findingsResponse, isLoading } = useListFindings({
    search: search || undefined,
    severity: severityFilter !== "all" ? severityFilter as any : undefined,
    validation_status: statusFilter !== "all" ? statusFilter as any : undefined,
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Findings Explorer</h1>
        <p className="text-muted-foreground">Investigate and validate discovered vulnerabilities across all scans.</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex flex-col md:flex-row items-center gap-4">
            <div className="relative flex-1 w-full">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search findings, endpoints, or CVEs..."
                className="pl-8"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-2 w-full md:w-auto">
              <Filter className="w-4 h-4 text-muted-foreground" />
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="info">Info</SelectItem>
                </SelectContent>
              </Select>
              
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-[160px]">
                  <SelectValue placeholder="Validation Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Statuses</SelectItem>
                  <SelectItem value="pending">Pending</SelectItem>
                  <SelectItem value="real">Real</SelectItem>
                  <SelectItem value="false_positive">False Positive</SelectItem>
                  <SelectItem value="informational">Informational</SelectItem>
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
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Title</th>
                  <th className="px-4 py-3">Target / Endpoint</th>
                  <th className="px-4 py-3">CVSS</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Discovered</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {isLoading ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                      Loading findings...
                    </td>
                  </tr>
                ) : findingsResponse?.items.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                      No findings matching your criteria.
                    </td>
                  </tr>
                ) : (
                  findingsResponse?.items.map((finding) => (
                    <tr 
                      key={finding.id} 
                      className="hover:bg-muted/20 cursor-pointer"
                      onClick={() => setLocation(`/findings/${finding.id}`)}
                    >
                      <td className="px-4 py-3 w-24">
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-foreground">{finding.title}</div>
                        <div className="text-xs text-muted-foreground">{finding.category}</div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-mono text-xs max-w-[300px] truncate">{finding.target_url}</div>
                        <div className="font-mono text-[10px] text-muted-foreground max-w-[300px] truncate" title={finding.endpoint}>{finding.endpoint}</div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs">
                        {finding.cvss_score ? finding.cvss_score.toFixed(1) : '-'}
                      </td>
                      <td className="px-4 py-3">
                        <Badge variant="outline" className={`text-[10px] capitalize ${
                          finding.validation_status === 'real' ? 'bg-red-500/10 text-red-500 border-red-500/20' :
                          finding.validation_status === 'false_positive' ? 'bg-green-500/10 text-green-500 border-green-500/20' :
                          finding.validation_status === 'informational' ? 'bg-blue-500/10 text-blue-500 border-blue-500/20' :
                          'bg-muted text-muted-foreground'
                        }`}>
                          {finding.validation_status.replace('_', ' ')}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-muted-foreground text-xs whitespace-nowrap">
                        {format(new Date(finding.created_at), "MMM d, yyyy")}
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
