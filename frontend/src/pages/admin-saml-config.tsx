import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Lock, CheckCircle2, XCircle, Copy, ExternalLink, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface SamlConfig {
  callback_url: string;
  entry_point: string;
  issuer: string;
  idp_cert_configured: boolean;
  private_key_configured: boolean;
  metadata_url: string;
  login_url: string;
  enabled: boolean;
}

export default function AdminSamlConfig() {
  const { toast } = useToast();

  const { data: config, isLoading } = useQuery<SamlConfig>({
    queryKey: ["/api/admin/saml-config"],
    queryFn: () => fetch("/api/admin/saml-config", { credentials: "include" }).then(r => r.json()),
  });

  const copy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: `${label} copied to clipboard` });
  };

  if (isLoading) {
    return <div className="flex justify-center py-12"><Loader2 className="w-6 h-6 animate-spin text-muted-foreground" /></div>;
  }

  const metadataFullUrl = config ? `${window.location.origin}${config.metadata_url}` : "";
  const loginFullUrl = config ? `${window.location.origin}${config.login_url}` : "";

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Lock className="w-6 h-6 text-blue-400" /> SAML 2.0 / SSO Configuration
        </h1>
        <p className="text-muted-foreground mt-1 text-sm">
          Configure enterprise Single Sign-On via SAML 2.0 (Okta, Azure AD, OneLogin, etc.)
        </p>
      </div>

      {/* Status */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            Status
            {config?.enabled ? (
              <Badge className="bg-green-500/10 text-green-400 border-green-500/20">Active</Badge>
            ) : (
              <Badge variant="outline" className="text-muted-foreground">Not Configured</Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4">
          {[
            { label: "Entry Point (IdP URL)", value: config?.entry_point || "Not set" },
            { label: "SP Issuer / Entity ID", value: config?.issuer || "bugfinder" },
            { label: "IdP Certificate", value: config?.idp_cert_configured ? "Configured" : "Missing", ok: config?.idp_cert_configured },
            { label: "SP Private Key", value: config?.private_key_configured ? "Configured" : "Missing", ok: config?.private_key_configured },
          ].map(item => (
            <div key={item.label} className="space-y-1">
              <p className="text-xs text-muted-foreground">{item.label}</p>
              <div className="flex items-center gap-1.5">
                {"ok" in item && (item.ok
                  ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                  : <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                )}
                <span className="text-sm font-medium truncate">{item.value}</span>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* SP Endpoints for IdP configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Service Provider Endpoints</CardTitle>
          <CardDescription>Copy these URLs into your Identity Provider configuration.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {[
            { label: "SP Metadata URL (upload to IdP)", url: metadataFullUrl },
            { label: "ACS / Callback URL", url: config?.callback_url ?? "" },
            { label: "SP Login URL (initiate SSO)", url: loginFullUrl },
          ].map(item => (
            <div key={item.label} className="space-y-1.5">
              <p className="text-xs text-muted-foreground">{item.label}</p>
              <div className="flex items-center gap-2">
                <code className="text-xs font-mono bg-muted px-2 py-1.5 rounded flex-1 truncate">
                  {item.url || "—"}
                </code>
                <Button variant="ghost" size="sm" className="h-7 px-2" onClick={() => copy(item.url, item.label)}>
                  <Copy className="w-3.5 h-3.5" />
                </Button>
                {item.label.includes("Metadata") && item.url && (
                  <Button variant="ghost" size="sm" className="h-7 px-2" asChild>
                    <a href={item.url} target="_blank" rel="noreferrer">
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  </Button>
                )}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Configuration instructions */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">How to Configure</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          <p>Set the following environment variables on the backend to enable SAML SSO:</p>
          <div className="rounded-md p-4 font-mono text-xs space-y-1" style={{ background: "hsl(var(--muted))" }}>
            <div><span className="text-purple-400">SAML_ENTRY_POINT</span>=https://your-idp.com/saml/sso</div>
            <div><span className="text-purple-400">SAML_CALLBACK_URL</span>={config?.callback_url ?? "https://your-app.com/api/auth/saml/callback"}</div>
            <div><span className="text-purple-400">SAML_ISSUER</span>=bugfinder</div>
            <div><span className="text-purple-400">SAML_IDP_CERT</span>={"<base64-encoded IdP X.509 certificate>"}</div>
            <div><span className="text-purple-400">SAML_PRIVATE_KEY</span>={"<SP private key PEM (optional, for signed requests)>"}</div>
          </div>
          <p className="text-xs">
            After setting env vars, restart the server. Users who login via SAML are automatically provisioned with role derived from their IdP group membership (admin, senior, analyst).
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
