import { useState } from "react";
import { Link, useLocation } from "wouter";
import { useListRemediations } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";
import { CheckSquare, ArrowRight, ExternalLink, Wrench } from "lucide-react";

export default function Remediations() {
  const [, setLocation] = useLocation();
  const { data: remediationsResponse, isLoading } = useListRemediations();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Remediations</h1>
        <p className="text-muted-foreground">Track and manage vulnerability fixes and patches.</p>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {isLoading ? (
          <div className="p-8 text-center text-muted-foreground bg-muted/20 rounded-lg border border-border">
            Loading remediation tasks...
          </div>
        ) : remediationsResponse?.items.length === 0 ? (
          <div className="p-8 text-center text-muted-foreground bg-muted/20 rounded-lg border border-border">
            No remediation tasks found. Create one from a finding detail page.
          </div>
        ) : (
          remediationsResponse?.items.map((remediation) => (
            <Card key={remediation.id} className="overflow-hidden">
              <div className="flex flex-col md:flex-row">
                <div className="flex-1 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center space-x-2">
                      <Wrench className="w-5 h-5 text-primary" />
                      <h3 className="font-semibold text-lg">{remediation.title}</h3>
                    </div>
                    <Badge variant="outline" className={`capitalize ${
                      remediation.status === 'pending' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' :
                      remediation.status === 'in_progress' ? 'bg-blue-500/10 text-blue-500 border-blue-500/20' :
                      remediation.status === 'resolved' ? 'bg-green-500/10 text-green-500 border-green-500/20' :
                      'bg-muted text-muted-foreground'
                    }`}>
                      {remediation.status.replace('_', ' ')}
                    </Badge>
                  </div>
                  
                  <p className="text-sm text-muted-foreground mb-4 max-w-3xl">
                    {remediation.description}
                  </p>
                  
                  {remediation.patch_snippet && (
                    <div className="mb-4 bg-muted/50 p-3 rounded-md border border-border">
                      <pre className="text-xs font-mono text-foreground overflow-x-auto whitespace-pre-wrap">
                        {remediation.patch_snippet}
                      </pre>
                    </div>
                  )}

                  <div className="flex items-center text-xs text-muted-foreground space-x-4">
                    <span>Created: {format(new Date(remediation.created_at), "MMM d, yyyy")}</span>
                  </div>
                </div>
                <div className="bg-muted/30 p-6 md:w-64 border-t md:border-t-0 md:border-l border-border flex flex-col justify-center">
                  <div className="space-y-3">
                    <Button variant="outline" className="w-full justify-between" onClick={() => setLocation(`/findings/${remediation.finding_id}`)}>
                      View Finding
                      <ExternalLink className="w-4 h-4 ml-2 text-muted-foreground" />
                    </Button>
                    {remediation.scan_job_id && (
                      <Button variant="ghost" className="w-full justify-between" onClick={() => setLocation(`/scans/${remediation.scan_job_id}`)}>
                        View Scan
                        <ArrowRight className="w-4 h-4 ml-2 text-muted-foreground" />
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
