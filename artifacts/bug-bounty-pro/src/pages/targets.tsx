import { useState } from "react";
import { Link } from "wouter";
import { useListTargets } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Search, ShieldAlert, Globe } from "lucide-react";
import { format } from "date-fns";

export default function Targets() {
  const [search, setSearch] = useState("");
  
  const { data: targetsResponse, isLoading } = useListTargets({
    search: search || undefined
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Targets Inventory</h1>
        <p className="text-muted-foreground">Manage and monitor all scanned domains and infrastructure.</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center space-x-2 w-full max-w-sm">
            <div className="relative flex-1">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search domains or URLs..."
                className="pl-8"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border border-border">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-muted-foreground uppercase bg-muted/50 border-b border-border">
                <tr>
                  <th className="px-4 py-3">Domain</th>
                  <th className="px-4 py-3">Risk Score</th>
                  <th className="px-4 py-3">Findings (Crit/High)</th>
                  <th className="px-4 py-3">Total Scans</th>
                  <th className="px-4 py-3">Last Scanned</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {isLoading ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                      Loading targets...
                    </td>
                  </tr>
                ) : targetsResponse?.items.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                      No targets found. Start by running a scan.
                    </td>
                  </tr>
                ) : (
                  targetsResponse?.items.map((target) => (
                    <tr key={target.id} className="hover:bg-muted/20">
                      <td className="px-4 py-3">
                        <div className="flex items-center font-mono">
                          <Globe className="w-4 h-4 mr-2 text-muted-foreground" />
                          <Link href={`/targets/${target.id}`} className="font-medium hover:underline text-primary">
                            {target.domain}
                          </Link>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`font-bold ${
                          target.risk_score > 80 ? 'text-[hsl(var(--critical))]' :
                          target.risk_score > 60 ? 'text-[hsl(var(--high))]' :
                          target.risk_score > 30 ? 'text-[hsl(var(--medium))]' :
                          'text-[hsl(var(--low))]'
                        }`}>
                          {target.risk_score}/100
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <ShieldAlert className="w-4 h-4 text-muted-foreground" />
                          <span>{target.total_findings}</span>
                          <span className="text-muted-foreground text-xs">
                            ({target.critical_findings} / {target.high_findings})
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs">{target.total_scans}</td>
                      <td className="px-4 py-3 text-muted-foreground text-xs whitespace-nowrap">
                        {target.last_scanned ? format(new Date(target.last_scanned), "MMM d, yyyy") : 'Never'}
                      </td>
                      <td className="px-4 py-3">
                        <Badge variant="outline" className={`capitalize ${
                          target.status === 'active' ? 'bg-green-500/10 text-green-500 border-green-500/20' :
                          'bg-muted text-muted-foreground'
                        }`}>
                          {target.status}
                        </Badge>
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
