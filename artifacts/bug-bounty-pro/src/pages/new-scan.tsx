import { useState } from "react";
import { useLocation } from "wouter";
import { useCreateScanJob } from "@workspace/api-client-react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { AlertCircle, Rocket, Shield, Zap } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export default function NewScan() {
  const [, setLocation] = useLocation();
  
  const [targetUrl, setTargetUrl] = useState("");
  const [profile, setProfile] = useState<"quick" | "standard" | "deep">("standard");
  const [validationEnabled, setValidationEnabled] = useState(true);
  const [fuzzingEnabled, setFuzzingEnabled] = useState(false);
  const [bugBountyMode, setBugBountyMode] = useState(false);
  const [engines, setEngines] = useState<string[]>(["nuclei", "nmap"]);
  const [authorized, setAuthorized] = useState(false);

  const createScan = useCreateScanJob({
    mutation: {
      onSuccess: (data) => {
        setLocation(`/scans/${data.id}`);
      }
    }
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl || !authorized) return;
    
    createScan.mutate({
      data: {
        target_url: targetUrl,
        scan_profile: profile,
        validation_enabled: validationEnabled,
        fuzzing_enabled: fuzzingEnabled,
        bug_bounty_mode: bugBountyMode,
        scanner_engines: engines
      }
    });
  };

  const handleEngineChange = (engine: string, checked: boolean) => {
    if (checked) {
      setEngines([...engines, engine]);
    } else {
      setEngines(engines.filter(e => e !== engine));
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Launch New Scan</h1>
        <p className="text-muted-foreground">Configure and initiate a new vulnerability assessment.</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
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
            <RadioGroup value={profile} onValueChange={(val: any) => setProfile(val)} className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <RadioGroupItem value="quick" id="quick" className="peer sr-only" />
                <Label
                  htmlFor="quick"
                  className="flex flex-col items-center justify-between rounded-md border-2 border-muted bg-popover p-4 hover:bg-accent hover:text-accent-foreground peer-data-[state=checked]:border-primary [&:has([data-state=checked])]:border-primary cursor-pointer"
                >
                  <Zap className="mb-3 h-6 w-6" />
                  <div className="font-semibold">Quick</div>
                  <div className="text-xs text-muted-foreground text-center mt-1">Lightweight checks, fast results</div>
                </Label>
              </div>
              <div>
                <RadioGroupItem value="standard" id="standard" className="peer sr-only" />
                <Label
                  htmlFor="standard"
                  className="flex flex-col items-center justify-between rounded-md border-2 border-muted bg-popover p-4 hover:bg-accent hover:text-accent-foreground peer-data-[state=checked]:border-primary [&:has([data-state=checked])]:border-primary cursor-pointer"
                >
                  <Shield className="mb-3 h-6 w-6" />
                  <div className="font-semibold">Standard</div>
                  <div className="text-xs text-muted-foreground text-center mt-1">Balanced depth and speed</div>
                </Label>
              </div>
              <div>
                <RadioGroupItem value="deep" id="deep" className="peer sr-only" />
                <Label
                  htmlFor="deep"
                  className="flex flex-col items-center justify-between rounded-md border-2 border-muted bg-popover p-4 hover:bg-accent hover:text-accent-foreground peer-data-[state=checked]:border-primary [&:has([data-state=checked])]:border-primary cursor-pointer"
                >
                  <Rocket className="mb-3 h-6 w-6" />
                  <div className="font-semibold">Deep</div>
                  <div className="text-xs text-muted-foreground text-center mt-1">Comprehensive exhaustive scan</div>
                </Label>
              </div>
            </RadioGroup>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Advanced Options</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label className="text-base">Vulnerability Validation</Label>
                <p className="text-sm text-muted-foreground">Automatically verify findings to reduce false positives.</p>
              </div>
              <Switch checked={validationEnabled} onCheckedChange={setValidationEnabled} />
            </div>
            
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label className="text-base">Active Fuzzing</Label>
                <p className="text-sm text-muted-foreground">Inject malformed payloads to discover edge cases.</p>
              </div>
              <Switch checked={fuzzingEnabled} onCheckedChange={setFuzzingEnabled} />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label className="text-base">Bug Bounty Mode</Label>
                <p className="text-sm text-muted-foreground">Optimize for high-impact, bounty-eligible vulnerabilities.</p>
              </div>
              <Switch checked={bugBountyMode} onCheckedChange={setBugBountyMode} />
            </div>

            <div className="space-y-3 pt-4 border-t border-border">
              <Label className="text-base">Scanner Engines</Label>
              <div className="grid grid-cols-2 gap-4">
                {["nuclei", "nmap", "ffuf", "sqlmap", "nikto"].map((engine) => (
                  <div key={engine} className="flex items-center space-x-2">
                    <Checkbox 
                      id={`engine-${engine}`} 
                      checked={engines.includes(engine)}
                      onCheckedChange={(checked) => handleEngineChange(engine, checked as boolean)}
                    />
                    <label
                      htmlFor={`engine-${engine}`}
                      className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 capitalize"
                    >
                      {engine}
                    </label>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        <Alert variant="destructive" className="bg-destructive/10 border-destructive/20 text-destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Authorization Required</AlertTitle>
          <AlertDescription>
            Active scanning can be disruptive and may be considered hostile without permission.
          </AlertDescription>
        </Alert>

        <Card>
          <CardFooter className="pt-6 flex justify-between items-center bg-muted/30">
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="authorized" 
                checked={authorized}
                onCheckedChange={(c) => setAuthorized(c as boolean)}
              />
              <label
                htmlFor="authorized"
                className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
              >
                I confirm I am authorized to scan this target
              </label>
            </div>
            <Button type="submit" disabled={!authorized || !targetUrl || createScan.isPending}>
              {createScan.isPending ? "Initializing..." : "Launch Scan"}
            </Button>
          </CardFooter>
        </Card>
      </form>
    </div>
  );
}
