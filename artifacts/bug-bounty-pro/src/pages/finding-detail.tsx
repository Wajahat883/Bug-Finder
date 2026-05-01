import { useParams, Link, useLocation } from "wouter";
import { 
  useGetFinding, 
  useUpdateFinding,
  useCreateRemediation
} from "@workspace/api-client-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  ShieldAlert, 
  Target, 
  ExternalLink, 
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Wrench
} from "lucide-react";
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
    <Badge className={`${colors[severity.toLowerCase()]} border-none uppercase text-xs px-2 py-1`}>
      {severity}
    </Badge>
  );
}

export default function FindingDetail() {
  const params = useParams();
  const [, setLocation] = useLocation();
  const findingId = params.id as string;

  const { data: finding, isLoading } = useGetFinding(findingId, {
    query: { enabled: !!findingId }
  });

  const updateFinding = useUpdateFinding({
    mutation: {
      onSuccess: () => {
        // Optimistic UI could be handled here or refetching is triggered by react-query
      }
    }
  });

  const createRemediation = useCreateRemediation({
    mutation: {
      onSuccess: (data) => {
        setLocation('/remediations');
      }
    }
  });

  if (isLoading) {
    return <div className="p-8 flex justify-center text-muted-foreground">Loading finding details...</div>;
  }

  if (!finding) {
    return <div className="p-8 text-center text-destructive">Finding not found</div>;
  }

  const handleUpdateStatus = (status: "real" | "false_positive" | "informational" | "pending") => {
    updateFinding.mutate({
      id: finding.id,
      data: { validation_status: status }
    });
  };

  const handleCreateRemediation = () => {
    createRemediation.mutate({
      data: {
        finding_id: finding.id,
        title: `Fix: ${finding.title}`,
        description: finding.recommended_fix || "Address the vulnerability described in the finding.",
        patch_snippet: "/* Add patch logic here */\n"
      }
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3 mb-2">
            <SeverityBadge severity={finding.severity} />
            <h1 className="text-2xl font-bold tracking-tight">{finding.title}</h1>
          </div>
          <div className="flex items-center space-x-4 text-sm text-muted-foreground">
            <span className="flex items-center">
              <Target className="w-4 h-4 mr-1.5" />
              {finding.target_url}
            </span>
            <span>Discovered: {format(new Date(finding.created_at), "MMM d, yyyy")}</span>
            <span>Scanner: <Badge variant="secondary" className="text-[10px]">{finding.scanner_name}</Badge></span>
          </div>
        </div>
        <div className="flex flex-col items-end space-y-2">
          <div className="flex space-x-2">
            <Button 
              variant={finding.validation_status === 'real' ? 'default' : 'outline'} 
              size="sm"
              className={finding.validation_status === 'real' ? 'bg-red-500 hover:bg-red-600 text-white' : ''}
              onClick={() => handleUpdateStatus('real')}
            >
              <AlertTriangle className="w-4 h-4 mr-1.5" />
              Valid
            </Button>
            <Button 
              variant={finding.validation_status === 'false_positive' ? 'default' : 'outline'} 
              size="sm"
              className={finding.validation_status === 'false_positive' ? 'bg-green-500 hover:bg-green-600 text-white' : ''}
              onClick={() => handleUpdateStatus('false_positive')}
            >
              <XCircle className="w-4 h-4 mr-1.5" />
              False Positive
            </Button>
            <Button 
              variant={finding.validation_status === 'informational' ? 'default' : 'outline'} 
              size="sm"
              className={finding.validation_status === 'informational' ? 'bg-blue-500 hover:bg-blue-600 text-white' : ''}
              onClick={() => handleUpdateStatus('informational')}
            >
              <Info className="w-4 h-4 mr-1.5" />
              Info
            </Button>
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground font-medium">CVSS Score</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono">{finding.cvss_score ? finding.cvss_score.toFixed(1) : 'N/A'}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground font-medium">CWE ID</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-muted-foreground">{finding.cwe_id || 'N/A'}</div>
          </CardContent>
        </Card>
        <Card className="col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground font-medium">Endpoint</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-sm font-mono truncate bg-muted/50 p-2 rounded border border-border">
              {finding.endpoint}
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="details" className="w-full">
        <TabsList className="w-full justify-start border-b border-border rounded-none bg-transparent h-auto p-0">
          <TabsTrigger value="details" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-6 py-3">
            Description
          </TabsTrigger>
          <TabsTrigger value="evidence" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-6 py-3">
            Evidence
          </TabsTrigger>
          <TabsTrigger value="remediation" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-6 py-3">
            Remediation
          </TabsTrigger>
        </TabsList>
        
        <TabsContent value="details" className="pt-6 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Vulnerability Details</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="prose prose-sm dark:prose-invert max-w-none">
                {finding.description.split('\n\n').map((p, i) => <p key={i}>{p}</p>)}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="evidence" className="pt-6">
          <Card>
            <CardHeader>
              <CardTitle>Proof of Concept / Evidence</CardTitle>
              <CardDescription>Raw HTTP requests, responses, or script execution outputs</CardDescription>
            </CardHeader>
            <CardContent>
              {finding.evidence ? (
                <pre className="p-4 bg-muted text-foreground font-mono text-xs overflow-x-auto rounded-md border border-border whitespace-pre-wrap break-all">
                  {finding.evidence}
                </pre>
              ) : (
                <div className="text-center py-12 text-muted-foreground">No specific evidence payload recorded.</div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="remediation" className="pt-6">
          <Card>
            <CardHeader>
              <CardTitle>Recommended Fix</CardTitle>
              <CardDescription>Guidance on how to resolve this vulnerability</CardDescription>
            </CardHeader>
            <CardContent>
              {finding.recommended_fix ? (
                <div className="prose prose-sm dark:prose-invert max-w-none mb-6">
                  {finding.recommended_fix.split('\n\n').map((p, i) => <p key={i}>{p}</p>)}
                </div>
              ) : (
                <div className="text-center py-6 text-muted-foreground mb-6">No specific remediation guidance provided.</div>
              )}
              
              <div className="border-t border-border pt-6 flex justify-between items-center">
                <div>
                  <h4 className="text-sm font-medium mb-1">Create Remediation Task</h4>
                  <p className="text-xs text-muted-foreground">Track the resolution of this vulnerability.</p>
                </div>
                <Button onClick={handleCreateRemediation} disabled={createRemediation.isPending}>
                  <Wrench className="w-4 h-4 mr-2" />
                  {createRemediation.isPending ? "Creating..." : "Track Remediation"}
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
