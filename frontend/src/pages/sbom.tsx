import { useParams } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Download, Shield, Package, AlertTriangle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

export default function SbomPage() {
  const { id } = useParams<{ id: string }>();
  const { data, isLoading } = useQuery({
    queryKey: ["/api/sbom", id],
    queryFn: () => fetch(`/api/sbom/${id}`, { credentials: "include" }).then(r => r.json()),
  });

  const components = data?.components ?? [];
  const vulnerabilities = data?.vulnerabilities ?? [];
  const vulnerableComponents = components.filter((c: any) => c.has_vulnerability).length;

  function downloadSbom(format: "cyclonedx" | "spdx") {
    const url = format === "cyclonedx" ? `/api/sbom/${id}/download` : `/api/sbom/${id}/spdx`;
    window.open(url, "_blank");
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Software Bill of Materials</h1>
          <p className="text-muted-foreground text-sm mt-1">Scan {id}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => downloadSbom("cyclonedx")}><Download className="w-4 h-4 mr-2"/>CycloneDX JSON</Button>
          <Button variant="outline" size="sm" onClick={() => downloadSbom("spdx")}><Download className="w-4 h-4 mr-2"/>SPDX JSON</Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Total Components", value: components.length, icon: Package, color: "text-blue-400" },
          { label: "Vulnerable", value: vulnerableComponents, icon: AlertTriangle, color: "text-orange-400" },
          { label: "Critical CVEs", value: vulnerabilities.filter((v: any) => v.ratings?.[0]?.severity === "critical").length, icon: Shield, color: "text-red-400" },
          { label: "Unique Packages", value: new Set(components.map((c: any) => c.name)).size, icon: Package, color: "text-green-400" },
        ].map(s => (
          <Card key={s.label}>
            <CardContent className="pt-4">
              <div className={`text-2xl font-bold ${s.color}`}>{isLoading ? <Skeleton className="h-8 w-12" /> : s.value}</div>
              <div className="text-xs text-muted-foreground mt-1">{s.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Vulnerabilities Table */}
      <Card>
        <CardHeader><CardTitle>Vulnerabilities</CardTitle></CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-xs text-muted-foreground border-b border-border">
                <th className="text-left py-2">CVE</th>
                <th className="text-left py-2">Component</th>
                <th className="text-left py-2">Severity</th>
                <th className="text-left py-2">CVSS</th>
                <th className="text-left py-2">EPSS</th>
                <th className="text-left py-2">Description</th>
              </tr></thead>
              <tbody>
                {isLoading ? Array.from({length:5}).map((_,i) => (
                  <tr key={i}><td colSpan={6} className="py-2"><Skeleton className="h-6 w-full" /></td></tr>
                )) : vulnerabilities.map((v: any) => (
                  <tr key={v.id} className="border-b border-border/30 hover:bg-accent/10">
                    <td className="py-2"><a href={`https://nvd.nist.gov/vuln/detail/${v.id}`} target="_blank" rel="noreferrer" className="text-blue-400 hover:underline font-mono text-xs">{v.id}</a></td>
                    <td className="py-2 text-xs">{v.affects?.[0]?.ref ?? "—"}</td>
                    <td className="py-2"><Badge variant={v.ratings?.[0]?.severity === "critical" ? "destructive" : "secondary"} className="text-xs">{v.ratings?.[0]?.severity ?? "—"}</Badge></td>
                    <td className="py-2 text-xs font-mono">{v.ratings?.[0]?.score ?? "—"}</td>
                    <td className="py-2 text-xs">{v.epss_score ? `${(v.epss_score * 100).toFixed(1)}%` : "—"}</td>
                    <td className="py-2 text-xs text-muted-foreground max-w-xs truncate">{v.description ?? "—"}</td>
                  </tr>
                ))}
                {!isLoading && vulnerabilities.length === 0 && (
                  <tr><td colSpan={6} className="py-8 text-center text-muted-foreground text-sm">No vulnerabilities found</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
