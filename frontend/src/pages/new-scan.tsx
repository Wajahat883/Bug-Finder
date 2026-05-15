import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useCreateScanJob } from "@/api-client";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Textarea } from "@/components/ui/textarea";
import { AlertCircle, Rocket, Shield, Zap, Lock, FileText, ChevronDown, ChevronUp, Bookmark, Brain, Loader2, X as XIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

const ENGINE_GROUPS: Record<string, string[]> = {
  "Web": ["xss", "sqli", "csrf", "cors", "idor", "redirect", "file-upload", "injection-advanced"],
  "Authentication": ["auth", "jwt", "oauth", "session-recorder"],
  "Infrastructure": ["headers", "tls", "ports", "subdomains", "dns", "fingerprint"],
  "Advanced": ["ssrf", "xxe", "graphql", "nuclei", "waf-bypass", "js-secrets", "dom-browser", "openapi", "business-logic", "cache-poisoning"],
};
const ALL_ENGINES = Object.values(ENGINE_GROUPS).flat();

const TIME_ESTIMATE: Record<string, string> = { quick: "~2 min", standard: "~5 min", deep: "~15 min", full: "~30 min", custom: "varies" };

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
}

export default function NewScan() {
  const [, setLocation] = useLocation();

  const [targetUrl, setTargetUrl] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get("url") ?? "";
  });
  const [profile, setProfile] = useState<"quick" | "standard" | "deep">("standard");
  const [validationEnabled, setValidationEnabled] = useState(true);
  const [fuzzingEnabled, setFuzzingEnabled] = useState(false);
  const [bugBountyMode, setBugBountyMode] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<string>("");
  const [templates, setTemplates] = useState<Template[]>([]);

  const [sessionCookie, setSessionCookie] = useState("");
  const [authToken, setAuthToken] = useState("");
  const [customHeadersRaw, setCustomHeadersRaw] = useState("");
  const [showAuthPanel, setShowAuthPanel] = useState(false);

  const [saveAsTemplate, setSaveAsTemplate] = useState(false);
  const [templateName, setTemplateName] = useState("");

  const [nlPrompt, setNlPrompt] = useState("");
  const [nlLoading, setNlLoading] = useState(false);
  const [maxFindings, setMaxFindings] = useState<number | "">("");
  const [maxDurationMin, setMaxDurationMin] = useState<number | "">("");

  // Engine selection state
  const [selectedEngines, setSelectedEngines] = useState<string[]>([...ALL_ENGINES]);
  const [enginesExpanded, setEnginesExpanded] = useState(false);

  // Advanced settings state
  const [advancedExpanded, setAdvancedExpanded] = useState(false);
  const [scanDepth, setScanDepth] = useState(3);
  const [timeoutMs, setTimeoutMs] = useState(5000);
  const [rateLimit, setRateLimit] = useState(10);
  const [excludedPaths, setExcludedPaths] = useState<string[]>([]);
  const [excludedPathInput, setExcludedPathInput] = useState("");
  const [customHeaders, setCustomHeaders] = useState<{ key: string; value: string }[]>([]);
  const [userAgent, setUserAgent] = useState("");
  const [credentialId, setCredentialId] = useState("");
  const [credentials, setCredentials] = useState<Array<{ id: string; name: string }>>([]);

  useEffect(() => {
    fetch("/api/credentials", { credentials: "include" })
      .then(r => r.json())
      .then(data => setCredentials(Array.isArray(data) ? data : (data?.items ?? [])))
      .catch(() => {});
  }, []);

  async function applyNaturalLanguageConfig() {
    if (!nlPrompt.trim()) return;
    setNlLoading(true);
    try {
      const r = await fetch("/api/ai/scan-config", { method: "POST", credentials: "include", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ prompt: nlPrompt }) });
      const cfg = await r.json();
      if (cfg.target_url) setTargetUrl(cfg.target_url);
      if (cfg.profile && ["quick","standard","deep"].includes(cfg.profile)) setProfile(cfg.profile);
      if (typeof cfg.validation_enabled === "boolean") setValidationEnabled(cfg.validation_enabled);
      if (typeof cfg.fuzzing_enabled === "boolean") setFuzzingEnabled(cfg.fuzzing_enabled);
      if (typeof cfg.bug_bounty_mode === "boolean") setBugBountyMode(cfg.bug_bounty_mode);
    } catch {}
    setNlLoading(false);
  }

  useEffect(() => {
    fetch("/api/scan-templates", { credentials: "include" })
      .then(r => r.json())
      .then(data => setTemplates(Array.isArray(data) ? data : []))
      .catch(() => {});
  }, []);

  const createScan = useCreateScanJob({
    mutation: {
      onSuccess: (data) => {
        setLocation(`/scans/${data.id}`);
      }
    }
  });

  const loadTemplate = (templateId: string) => {
    const tmpl = templates.find(t => t.id === templateId);
    if (!tmpl) return;
    setSelectedTemplate(templateId);
    setProfile(tmpl.scan_profile as "quick" | "standard" | "deep");
    setValidationEnabled(tmpl.validation_enabled);
    setFuzzingEnabled(tmpl.fuzzing_enabled);
    setBugBountyMode(tmpl.bug_bounty_mode);
  };

  const parseCustomHeaders = (): Record<string, string> | undefined => {
    if (!customHeadersRaw.trim()) return undefined;
    const headers: Record<string, string> = {};
    for (const line of customHeadersRaw.split("\n")) {
      const idx = line.indexOf(":");
      if (idx > 0) {
        headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      }
    }
    return Object.keys(headers).length > 0 ? headers : undefined;
  };

  const handleSaveTemplate = async () => {
    if (!templateName.trim()) return;
    try {
      await fetch("/api/scan-templates", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: templateName,
          scan_profile: profile,
          validation_enabled: validationEnabled,
          fuzzing_enabled: fuzzingEnabled,
          bug_bounty_mode: bugBountyMode,
        }),
      });
      const refreshed = await fetch("/api/scan-templates", { credentials: "include" }).then(r => r.json());
      setTemplates(Array.isArray(refreshed) ? refreshed : []);
      setSaveAsTemplate(false);
      setTemplateName("");
    } catch (e) {
      console.error(e);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl || !authorized) return;

    const parsedCustomHeaders = parseCustomHeaders();

    createScan.mutate({
      data: {
        target_url: targetUrl,
        scan_profile: profile,
        validation_enabled: validationEnabled,
        fuzzing_enabled: fuzzingEnabled,
        bug_bounty_mode: bugBountyMode,
        authorization_acknowledged: authorized,
        template_id: selectedTemplate || undefined,
        session_cookie: sessionCookie || undefined,
        auth_token: authToken || undefined,
        custom_headers: parsedCustomHeaders as Record<string, string> | undefined,
        max_findings: maxFindings !== "" ? Number(maxFindings) : undefined,
        max_duration_minutes: maxDurationMin !== "" ? Number(maxDurationMin) : undefined,
        engines: selectedEngines,
        advanced_config: {
          depth: scanDepth,
          timeout_ms: timeoutMs,
          rate_limit: rateLimit,
          excluded_paths: excludedPaths,
          custom_headers: customHeaders,
          user_agent: userAgent || undefined,
          credential_id: credentialId || undefined,
        },
      } as any
    });
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Launch New Scan</h1>
        <p className="text-muted-foreground">Configure and initiate a new vulnerability assessment.</p>
      </div>

      {templates.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2">
              <Bookmark className="w-4 h-4" /> Scan Templates
            </CardTitle>
            <CardDescription>Load a pre-configured scan template to start quickly</CardDescription>
          </CardHeader>
          <CardContent>
            <Select value={selectedTemplate} onValueChange={loadTemplate}>
              <SelectTrigger>
                <SelectValue placeholder="Choose a template (optional)..." />
              </SelectTrigger>
              <SelectContent>
                {templates.map(t => (
                  <SelectItem key={t.id} value={t.id}>
                    <div className="flex items-center gap-2">
                      {t.name}
                      {t.is_builtin && <Badge variant="outline" className="text-xs">Built-in</Badge>}
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {selectedTemplate && (() => {
              const tmpl = templates.find(t => t.id === selectedTemplate);
              return tmpl && (
                <p className="text-sm text-muted-foreground mt-2">{tmpl.description}</p>
              );
            })()}
          </CardContent>
        </Card>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        <Card className="border-primary/30 bg-primary/5">
          <CardContent className="pt-4">
            <Label className="text-xs mb-1 flex items-center gap-1"><Brain className="w-3.5 h-3.5" /> Natural Language Config (AI)</Label>
            <div className="flex gap-2 mt-1">
              <Input value={nlPrompt} onChange={e => setNlPrompt(e.target.value)} placeholder='e.g. "Deep scan example.com for OWASP Top 10, enable fuzzing"' className="text-sm" />
              <Button type="button" variant="outline" size="sm" onClick={applyNaturalLanguageConfig} disabled={nlLoading || !nlPrompt.trim()}>
                {nlLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : "Parse"}
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Target Specification</CardTitle>
            <CardDescription>Enter the URL or IP address of the target system.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Label htmlFor="target_url">Target URL</Label>
              <Input
                id="target_url"
                placeholder="https://example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                required
                className="font-mono text-lg py-6"
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Scan Profile</CardTitle>
            <CardDescription>Select the depth and aggressiveness of the scan.</CardDescription>
          </CardHeader>
          <CardContent>
            <RadioGroup value={profile} onValueChange={(val: string) => setProfile(val as "quick" | "standard" | "deep")} className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                { value: "quick", icon: Zap, label: "Quick", desc: "8 scanners · ~2 min", modules: "TLS, Headers, Cookies, JS Secrets, CVE, Recon, DNS" },
                { value: "standard", icon: Shield, label: "Standard", desc: "17 scanners · ~8 min", modules: "All quick + CORS, XSS, SQLi, JWT, GraphQL, Rate Limit, Dep Confusion" },
                { value: "deep", icon: Rocket, label: "Deep", desc: "28 scanners · ~20 min", modules: "All standard + IDOR, SSRF, SSTI, CRLF, Subdomains, Wayback, File Upload, Smuggling" },
              ].map(({ value, icon: Icon, label, desc, modules }) => (
                <div key={value}>
                  <RadioGroupItem value={value} id={value} className="peer sr-only" />
                  <Label
                    htmlFor={value}
                    className="flex flex-col rounded-md border-2 border-muted bg-popover p-4 hover:bg-accent hover:text-accent-foreground peer-data-[state=checked]:border-primary [&:has([data-state=checked])]:border-primary cursor-pointer"
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <Icon className="h-5 w-5" />
                      <span className="font-semibold">{label}</span>
                    </div>
                    <span className="text-xs font-medium text-muted-foreground">{desc}</span>
                    <span className="text-xs text-muted-foreground/70 mt-1">{modules}</span>
                  </Label>
                </div>
              ))}
            </RadioGroup>
            <p className="text-xs text-muted-foreground mt-3">Estimated time: {TIME_ESTIMATE[profile] ?? "varies"}</p>
          </CardContent>
        </Card>

        {/* Engine Selection */}
        <Card>
          <CardHeader>
            <button
              type="button"
              className="flex items-center justify-between w-full"
              onClick={() => setEnginesExpanded(v => !v)}
            >
              <div>
                <CardTitle className="text-base text-left">Select Scan Engines</CardTitle>
                <p className="text-sm text-muted-foreground font-normal text-left">
                  {selectedEngines.length}/{ALL_ENGINES.length} engines selected
                </p>
              </div>
              {enginesExpanded ? <ChevronUp className="w-4 h-4 shrink-0" /> : <ChevronDown className="w-4 h-4 shrink-0" />}
            </button>
          </CardHeader>
          {enginesExpanded && (
            <CardContent className="space-y-5 pt-0">
              {Object.entries(ENGINE_GROUPS).map(([groupName, groupEngines]) => {
                const allSelected = groupEngines.every(e => selectedEngines.includes(e));
                const noneSelected = groupEngines.every(e => !selectedEngines.includes(e));
                return (
                  <div key={groupName}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-semibold">{groupName}</span>
                      <div className="flex gap-2">
                        <button type="button" className="text-xs text-primary hover:underline" onClick={() => {
                          setSelectedEngines(prev => Array.from(new Set([...prev, ...groupEngines])));
                        }} disabled={allSelected}>Select All</button>
                        <span className="text-muted-foreground">·</span>
                        <button type="button" className="text-xs text-muted-foreground hover:underline" onClick={() => {
                          setSelectedEngines(prev => prev.filter(e => !groupEngines.includes(e)));
                        }} disabled={noneSelected}>None</button>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                      {groupEngines.map(engine => (
                        <div key={engine} className="flex items-center gap-2">
                          <Checkbox
                            id={`engine-${engine}`}
                            checked={selectedEngines.includes(engine)}
                            onCheckedChange={(checked) => {
                              setSelectedEngines(prev =>
                                checked ? [...prev, engine] : prev.filter(e => e !== engine)
                              );
                            }}
                          />
                          <label htmlFor={`engine-${engine}`} className="text-xs capitalize cursor-pointer select-none">
                            {engine.replace(/-/g, " ")}
                          </label>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </CardContent>
          )}
        </Card>

        {/* Advanced Settings */}
        <Card>
          <CardHeader>
            <button
              type="button"
              className="flex items-center justify-between w-full"
              onClick={() => setAdvancedExpanded(v => !v)}
            >
              <div>
                <CardTitle className="text-base text-left">Advanced Settings</CardTitle>
                <p className="text-sm text-muted-foreground font-normal text-left">Depth, timeouts, rate limits, headers</p>
              </div>
              {advancedExpanded ? <ChevronUp className="w-4 h-4 shrink-0" /> : <ChevronDown className="w-4 h-4 shrink-0" />}
            </button>
          </CardHeader>
          {advancedExpanded && (
            <CardContent className="space-y-6 pt-0">
              {/* Scan Depth */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-sm">Scan Depth</Label>
                  <span className="text-sm font-mono text-primary">{scanDepth}</span>
                </div>
                <input type="range" min={1} max={5} value={scanDepth} onChange={e => setScanDepth(Number(e.target.value))} className="w-full accent-primary" />
                <p className="text-xs text-muted-foreground">1 = shallow crawl, 5 = exhaustive crawl</p>
              </div>

              {/* Request Timeout */}
              <div className="space-y-2">
                <Label htmlFor="timeoutMs" className="text-sm">Request Timeout (ms)</Label>
                <Input
                  id="timeoutMs"
                  type="number"
                  min={1000}
                  max={30000}
                  step={500}
                  value={timeoutMs}
                  onChange={e => setTimeoutMs(Number(e.target.value))}
                  className="h-9"
                />
              </div>

              {/* Rate Limit */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-sm">Rate Limit</Label>
                  <span className="text-sm font-mono text-primary">{rateLimit} req/sec</span>
                </div>
                <input type="range" min={1} max={50} value={rateLimit} onChange={e => setRateLimit(Number(e.target.value))} className="w-full accent-primary" />
              </div>

              {/* Excluded Paths */}
              <div className="space-y-2">
                <Label className="text-sm">Excluded Paths</Label>
                <div className="flex gap-2">
                  <Input
                    placeholder="/admin, /logout"
                    value={excludedPathInput}
                    onChange={e => setExcludedPathInput(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        const val = excludedPathInput.trim();
                        if (val && !excludedPaths.includes(val)) setExcludedPaths(prev => [...prev, val]);
                        setExcludedPathInput("");
                      }
                    }}
                    className="h-9 text-sm"
                  />
                </div>
                {excludedPaths.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {excludedPaths.map(p => (
                      <Badge key={p} variant="secondary" className="gap-1 text-xs pr-1">
                        {p}
                        <button type="button" onClick={() => setExcludedPaths(prev => prev.filter(x => x !== p))}>
                          <XIcon className="w-3 h-3" />
                        </button>
                      </Badge>
                    ))}
                  </div>
                )}
                <p className="text-xs text-muted-foreground">Press Enter to add a path</p>
              </div>

              {/* Custom Headers */}
              <div className="space-y-2">
                <Label className="text-sm">Custom Headers</Label>
                {customHeaders.length > 0 && (
                  <div className="border rounded-md overflow-hidden">
                    <table className="w-full text-sm">
                      <thead className="bg-muted/50 text-xs">
                        <tr>
                          <th className="px-3 py-1.5 text-left">Key</th>
                          <th className="px-3 py-1.5 text-left">Value</th>
                          <th className="w-8" />
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {customHeaders.map((h, i) => (
                          <tr key={i}>
                            <td className="px-3 py-1">
                              <Input
                                value={h.key}
                                onChange={e => setCustomHeaders(prev => prev.map((x, idx) => idx === i ? { ...x, key: e.target.value } : x))}
                                className="h-7 text-xs font-mono border-0 p-0 bg-transparent focus-visible:ring-0"
                              />
                            </td>
                            <td className="px-3 py-1">
                              <Input
                                value={h.value}
                                onChange={e => setCustomHeaders(prev => prev.map((x, idx) => idx === i ? { ...x, value: e.target.value } : x))}
                                className="h-7 text-xs font-mono border-0 p-0 bg-transparent focus-visible:ring-0"
                              />
                            </td>
                            <td className="px-2 py-1">
                              <button type="button" onClick={() => setCustomHeaders(prev => prev.filter((_, idx) => idx !== i))} className="text-muted-foreground hover:text-destructive">
                                <XIcon className="w-3.5 h-3.5" />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <Button type="button" size="sm" variant="outline" className="h-8 text-xs" onClick={() => setCustomHeaders(prev => [...prev, { key: "", value: "" }])}>
                  + Add Header
                </Button>
              </div>

              {/* User Agent */}
              <div className="space-y-2">
                <Label htmlFor="userAgent" className="text-sm">User-Agent</Label>
                <Input
                  id="userAgent"
                  placeholder="Default (Bug Finder Pro/1.0)"
                  value={userAgent}
                  onChange={e => setUserAgent(e.target.value)}
                  className="h-9 text-sm font-mono"
                />
              </div>

              {/* Auth Credential */}
              {credentials.length > 0 && (
                <div className="space-y-2">
                  <Label className="text-sm">Auth Credential</Label>
                  <Select value={credentialId} onValueChange={setCredentialId}>
                    <SelectTrigger className="h-9">
                      <SelectValue placeholder="Select a saved credential..." />
                    </SelectTrigger>
                    <SelectContent>
                      {credentials.map(c => (
                        <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}
            </CardContent>
          )}
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Advanced Options</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {[
              { label: "Vulnerability Validation", desc: "Automatically verify findings to reduce false positives.", value: validationEnabled, onChange: setValidationEnabled },
              { label: "Active Fuzzing", desc: "Inject malformed payloads to discover edge cases.", value: fuzzingEnabled, onChange: setFuzzingEnabled },
              { label: "Bug Bounty Mode", desc: "Optimize for high-impact, bounty-eligible vulnerabilities (IDOR, auth, SSRF).", value: bugBountyMode, onChange: setBugBountyMode },
            ].map(({ label, desc, value, onChange }) => (
              <div key={label} className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="text-base">{label}</Label>
                  <p className="text-sm text-muted-foreground">{desc}</p>
                </div>
                <Switch checked={value} onCheckedChange={onChange} />
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <button
              type="button"
              className="flex items-center justify-between w-full"
              onClick={() => setShowAuthPanel(v => !v)}
            >
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-primary" />
                <div>
                  <CardTitle className="text-base">Authenticated Scanning</CardTitle>
                  <p className="text-sm text-muted-foreground font-normal">Provide credentials to test authenticated endpoints</p>
                </div>
              </div>
              {showAuthPanel ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          </CardHeader>
          {showAuthPanel && (
            <CardContent className="space-y-4 pt-0">
              <Tabs defaultValue="cookie">
                <TabsList className="w-full">
                  <TabsTrigger value="cookie" className="flex-1">Session Cookie</TabsTrigger>
                  <TabsTrigger value="token" className="flex-1">Bearer Token</TabsTrigger>
                  <TabsTrigger value="headers" className="flex-1">Custom Headers</TabsTrigger>
                </TabsList>
                <TabsContent value="cookie" className="space-y-2">
                  <Label htmlFor="session_cookie">Session Cookie</Label>
                  <Input
                    id="session_cookie"
                    placeholder="session=abc123; auth_token=xyz..."
                    value={sessionCookie}
                    onChange={(e) => setSessionCookie(e.target.value)}
                    className="font-mono text-sm"
                  />
                  <p className="text-xs text-muted-foreground">Paste the Cookie header value from an authenticated browser session</p>
                </TabsContent>
                <TabsContent value="token" className="space-y-2">
                  <Label htmlFor="auth_token">Authorization Token</Label>
                  <Input
                    id="auth_token"
                    placeholder="eyJhbGciOiJIUzI1NiJ9..."
                    value={authToken}
                    onChange={(e) => setAuthToken(e.target.value)}
                    className="font-mono text-sm"
                  />
                  <p className="text-xs text-muted-foreground">JWT or API token — will be sent as Authorization: Bearer {'<token>'}</p>
                </TabsContent>
                <TabsContent value="headers" className="space-y-2">
                  <Label htmlFor="custom_headers">Custom Request Headers</Label>
                  <Textarea
                    id="custom_headers"
                    placeholder={"X-API-Key: your-key-here\nX-Custom-Header: value"}
                    value={customHeadersRaw}
                    onChange={(e) => setCustomHeadersRaw(e.target.value)}
                    rows={4}
                    className="font-mono text-sm"
                  />
                  <p className="text-xs text-muted-foreground">One header per line in Key: Value format</p>
                </TabsContent>
              </Tabs>
              {(sessionCookie || authToken) && (
                <Alert className="bg-emerald-500/10 border-emerald-500/20 text-emerald-400">
                  <Lock className="h-4 w-4" />
                  <AlertTitle>Authenticated Scan Mode Active</AlertTitle>
                  <AlertDescription>Scanners will include your credentials to test post-login functionality</AlertDescription>
                </Alert>
              )}
            </CardContent>
          )}
        </Card>

        {/* Budget Limits */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Lock className="w-4 h-4 text-primary" />Scan Budget Limits
            </CardTitle>
            <CardDescription>Optionally cap scan cost by findings count or time.</CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <Label htmlFor="maxFindings" className="text-sm">Max Findings</Label>
              <Input id="maxFindings" type="number" min={1} placeholder="e.g. 100"
                value={maxFindings} onChange={e => setMaxFindings(e.target.value === "" ? "" : Number(e.target.value))}
                className="h-9" />
              <p className="text-xs text-muted-foreground">Stop after this many findings</p>
            </div>
            <div className="space-y-1">
              <Label htmlFor="maxDuration" className="text-sm">Max Duration (minutes)</Label>
              <Input id="maxDuration" type="number" min={1} placeholder="e.g. 60"
                value={maxDurationMin} onChange={e => setMaxDurationMin(e.target.value === "" ? "" : Number(e.target.value))}
                className="h-9" />
              <p className="text-xs text-muted-foreground">Stop after this many minutes</p>
            </div>
          </CardContent>
        </Card>

        <Alert variant="destructive" className="bg-destructive/10 border-destructive/20 text-destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Authorization Required</AlertTitle>
          <AlertDescription>
            Active scanning can be disruptive and may be considered hostile without permission. Only scan systems you own or have explicit written authorization to test.
          </AlertDescription>
        </Alert>

        <Card>
          <CardContent className="pt-6 space-y-4">
            {saveAsTemplate ? (
              <div className="space-y-2 p-4 border rounded-lg bg-muted/30">
                <Label>Template Name</Label>
                <div className="flex gap-2">
                  <Input placeholder="My Custom Template" value={templateName} onChange={e => setTemplateName(e.target.value)} />
                  <Button type="button" variant="outline" onClick={handleSaveTemplate} disabled={!templateName}>Save</Button>
                  <Button type="button" variant="ghost" onClick={() => setSaveAsTemplate(false)}>Cancel</Button>
                </div>
              </div>
            ) : (
              <button
                type="button"
                className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
                onClick={() => setSaveAsTemplate(true)}
              >
                <FileText className="w-4 h-4" /> Save current settings as a template
              </button>
            )}
          </CardContent>
          <CardFooter className="flex justify-between items-center bg-muted/30 border-t">
            <div className="flex items-center space-x-2">
              <Checkbox
                id="authorized"
                checked={authorized}
                onCheckedChange={(c) => setAuthorized(c as boolean)}
              />
              <label htmlFor="authorized" className="text-sm font-medium">
                I confirm I am authorized to scan this target
              </label>
            </div>
            <Button type="submit" disabled={!authorized || !targetUrl || createScan.isPending} className="min-w-32">
              {createScan.isPending ? "Launching..." : "Launch Scan"}
            </Button>
          </CardFooter>
        </Card>
      </form>
    </div>
  );
}
