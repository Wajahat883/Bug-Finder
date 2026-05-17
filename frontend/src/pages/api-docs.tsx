import { useState } from "react";
import { Download, Play, ChevronDown, ChevronRight } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";

const METHOD_COLORS: Record<string, string> = {
  GET: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  POST: "bg-green-500/20 text-green-400 border-green-500/30",
  PATCH: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  DELETE: "bg-red-500/20 text-red-400 border-red-500/30",
  PUT: "bg-purple-500/20 text-purple-400 border-purple-500/30",
};

const API_REFERENCE = [
  // Auth
  { method: "POST", path: "/api/auth/login", category: "Authentication", description: "Login with email and password" },
  { method: "POST", path: "/api/auth/logout", category: "Authentication", description: "End current session" },
  { method: "GET", path: "/api/auth/me", category: "Authentication", description: "Get current user profile" },
  // Scans
  { method: "GET", path: "/api/scans", category: "Scans", description: "List all scan jobs" },
  { method: "POST", path: "/api/scans", category: "Scans", description: "Start a new scan" },
  { method: "GET", path: "/api/scans/:id", category: "Scans", description: "Get scan details and progress" },
  { method: "DELETE", path: "/api/scans/:id", category: "Scans", description: "Cancel or delete a scan" },
  { method: "PATCH", path: "/api/scans/:id/pause", category: "Scans", description: "Pause a running scan" },
  { method: "PATCH", path: "/api/scans/:id/resume", category: "Scans", description: "Resume a paused scan" },
  // Findings
  { method: "GET", path: "/api/findings", category: "Findings", description: "List findings with filters (severity, status, target)" },
  { method: "GET", path: "/api/findings/:id", category: "Findings", description: "Get finding details including CVE enrichment" },
  { method: "PATCH", path: "/api/findings/:id", category: "Findings", description: "Update finding status or assign" },
  { method: "PATCH", path: "/api/findings/bulk", category: "Findings", description: "Bulk update multiple findings" },
  { method: "POST", path: "/api/findings/:id/false-positive", category: "Findings", description: "Mark as false positive with reason" },
  // Targets
  { method: "GET", path: "/api/targets", category: "Targets", description: "List all scan targets" },
  { method: "POST", path: "/api/targets", category: "Targets", description: "Add a new scan target" },
  { method: "DELETE", path: "/api/targets/:id", category: "Targets", description: "Remove a target" },
  // Reports
  { method: "GET", path: "/api/reports", category: "Reports", description: "List generated reports" },
  { method: "GET", path: "/api/reports/:id/pdf", category: "Reports", description: "Download report as PDF" },
  // Integrations
  { method: "GET", path: "/api/integrations/connections", category: "Integrations", description: "List OAuth-connected integrations" },
  { method: "GET", path: "/api/integrations/oauth/:service/begin", category: "Integrations", description: "Start OAuth flow for a service" },
  { method: "POST", path: "/api/integrations/jira/create-issue-oauth", category: "Integrations", description: "Create Jira ticket from a finding" },
  { method: "POST", path: "/api/integrations/github/create-issue-oauth", category: "Integrations", description: "Create GitHub issue from a finding" },
  { method: "POST", path: "/api/integrations/slack/notify", category: "Integrations", description: "Send Slack notification for a finding" },
  // Admin
  { method: "GET", path: "/api/audit-log", category: "Admin", description: "Get audit log entries (admin only)" },
  { method: "GET", path: "/api/admin/users", category: "Admin", description: "List all users (admin only)" },
  { method: "PUT", path: "/api/admin/policy", category: "Admin", description: "Update platform security policy" },
  { method: "GET", path: "/api/analytics/metrics/executive", category: "Analytics", description: "Get executive KPI metrics" },
  { method: "GET", path: "/api/analytics/anomalies", category: "Analytics", description: "Get detected metric anomalies" },
  { method: "GET", path: "/api/sbom/:scanId", category: "SBOM", description: "Get CycloneDX SBOM for a scan" },
];

const CATEGORIES = [...new Set(API_REFERENCE.map(e => e.category))];

function curlSnippet(method: string, path: string) {
  return `curl -X ${method} https://your-instance.com${path} \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json"`;
}

function pythonSnippet(method: string, path: string) {
  return `import requests
r = requests.${method.toLowerCase()}(
  "https://your-instance.com${path}",
  headers={"Authorization": "Bearer YOUR_API_KEY"}
)
print(r.json())`;
}

export default function ApiDocs() {
  const [activeCategory, setActiveCategory] = useState("Scans");
  const [tryItPath, setTryItPath] = useState<string | null>(null);
  const [tryItMethod, setTryItMethod] = useState("GET");
  const [requestBody, setRequestBody] = useState("{}");
  const [response, setResponse] = useState<string | null>(null);
  const [snippetTab, setSnippetTab] = useState<"curl" | "python">("curl");
  const [expandedEndpoint, setExpandedEndpoint] = useState<string | null>(null);

  const filtered = API_REFERENCE.filter(e => e.category === activeCategory);

  async function runRequest() {
    try {
      const opts: RequestInit = { method: tryItMethod, credentials: "include", headers: { "Content-Type": "application/json" } };
      if (tryItMethod !== "GET" && requestBody !== "{}") opts.body = requestBody;
      const r = await fetch(tryItPath!, opts);
      const data = await r.json();
      setResponse(JSON.stringify(data, null, 2));
    } catch (e) {
      setResponse(String(e));
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">API Documentation</h1>
          <p className="text-muted-foreground text-sm mt-1">Bug Finder Pro REST API — v1.0</p>
        </div>
        <Button variant="outline" onClick={() => window.open("/api/openapi.json", "_blank")}>
          <Download className="w-4 h-4 mr-2" />Download OpenAPI Spec
        </Button>
      </div>

      <div className="flex gap-6">
        {/* Sidebar categories */}
        <div className="w-48 shrink-0 space-y-1">
          {CATEGORIES.map(cat => (
            <button key={cat} onClick={() => setActiveCategory(cat)}
              className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${activeCategory === cat ? "bg-primary/10 text-primary font-medium" : "hover:bg-accent/50 text-muted-foreground"}`}>
              {cat}
            </button>
          ))}
        </div>

        {/* Endpoint list */}
        <div className="flex-1 space-y-2">
          {filtered.map(endpoint => {
            const key = `${endpoint.method}:${endpoint.path}`;
            const expanded = expandedEndpoint === key;
            return (
              <Card key={key} className="overflow-hidden">
                <button className="w-full flex items-center gap-3 p-4 hover:bg-accent/10 text-left" onClick={() => setExpandedEndpoint(expanded ? null : key)}>
                  <Badge className={`font-mono text-xs px-2 ${METHOD_COLORS[endpoint.method] ?? ""}`}>{endpoint.method}</Badge>
                  <code className="text-sm flex-1">{endpoint.path}</code>
                  <span className="text-sm text-muted-foreground">{endpoint.description}</span>
                  {expanded ? <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0" /> : <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />}
                </button>
                {expanded && (
                  <div className="border-t border-border p-4 space-y-4 bg-muted/20">
                    {/* Code snippets */}
                    <div>
                      <div className="flex gap-2 mb-2">
                        {(["curl", "python"] as const).map(t => (
                          <button key={t} onClick={() => setSnippetTab(t)} className={`px-3 py-1 text-xs rounded ${snippetTab === t ? "bg-primary text-primary-foreground" : "bg-muted"}`}>{t}</button>
                        ))}
                      </div>
                      <pre className="bg-muted rounded p-3 text-xs font-mono overflow-x-auto">
                        {snippetTab === "curl" ? curlSnippet(endpoint.method, endpoint.path) : pythonSnippet(endpoint.method, endpoint.path)}
                      </pre>
                    </div>
                    {/* Try it */}
                    <div>
                      <p className="text-xs font-medium mb-2">Try It</p>
                      {endpoint.method !== "GET" && <Textarea value={requestBody} onChange={e => setRequestBody(e.target.value)} placeholder='{"key": "value"}' className="font-mono text-xs mb-2 h-24" />}
                      <Button size="sm" onClick={() => { setTryItPath(endpoint.path); setTryItMethod(endpoint.method); runRequest(); }}>
                        <Play className="w-3 h-3 mr-1" />Send Request
                      </Button>
                      {response && <pre className="mt-2 bg-muted rounded p-3 text-xs font-mono overflow-x-auto max-h-48">{response}</pre>}
                    </div>
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      </div>
    </div>
  );
}
