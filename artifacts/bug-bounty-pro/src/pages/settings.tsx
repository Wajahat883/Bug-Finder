import { useState, useEffect } from "react";
import { useGetSettings, useUpdateSettings } from "@workspace/api-client-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Save, Key, Webhook, Bell, BrainCircuit, Activity } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export default function Settings() {
  const { toast } = useToast();
  const { data: settings, isLoading } = useGetSettings();
  
  const [formData, setFormData] = useState({
    default_export_format: "json",
    webhook_url: "",
    notifications_enabled: false,
    ai_analysis_enabled: true,
    max_concurrent_scans: 3,
  });

  useEffect(() => {
    if (settings) {
      setFormData({
        default_export_format: settings.default_export_format,
        webhook_url: settings.webhook_url || "",
        notifications_enabled: settings.notifications_enabled,
        ai_analysis_enabled: settings.ai_analysis_enabled,
        max_concurrent_scans: settings.max_concurrent_scans,
      });
    }
  }, [settings]);

  const updateSettings = useUpdateSettings({
    mutation: {
      onSuccess: () => {
        toast({
          title: "Settings saved",
          description: "Your platform configuration has been updated successfully.",
        });
      },
      onError: () => {
        toast({
          title: "Error saving settings",
          description: "An error occurred while updating the configuration.",
          variant: "destructive",
        });
      }
    }
  });

  const handleSave = () => {
    updateSettings.mutate({ data: formData });
  };

  if (isLoading) {
    return <div className="p-8 text-center text-muted-foreground">Loading settings...</div>;
  }

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Platform Settings</h1>
        <p className="text-muted-foreground">Configure global platform behavior and integrations.</p>
      </div>

      <div className="grid gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Activity className="w-5 h-5 mr-2 text-primary" />
              Engine Configuration
            </CardTitle>
            <CardDescription>Manage scan concurrency and behavior</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <Label>Maximum Concurrent Scans</Label>
                <span className="font-mono text-sm bg-muted px-2 py-1 rounded">{formData.max_concurrent_scans}</span>
              </div>
              <Slider 
                value={[formData.max_concurrent_scans]} 
                min={1} 
                max={10} 
                step={1}
                onValueChange={(val) => setFormData({...formData, max_concurrent_scans: val[0]})}
              />
              <p className="text-xs text-muted-foreground">Higher concurrency requires more system resources.</p>
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label className="flex items-center">
                  <BrainCircuit className="w-4 h-4 mr-2" />
                  AI Analysis Engine
                </Label>
                <p className="text-sm text-muted-foreground">Automatically generate executive summaries for scan results.</p>
              </div>
              <Switch 
                checked={formData.ai_analysis_enabled}
                onCheckedChange={(c) => setFormData({...formData, ai_analysis_enabled: c})}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Webhook className="w-5 h-5 mr-2 text-primary" />
              Integrations & Export
            </CardTitle>
            <CardDescription>Configure external hooks and data formats</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-2">
              <Label>Global Webhook URL</Label>
              <Input 
                placeholder="https://your-domain.com/webhook" 
                value={formData.webhook_url}
                onChange={(e) => setFormData({...formData, webhook_url: e.target.value})}
              />
              <p className="text-xs text-muted-foreground">Called when high/critical findings are discovered or scans complete.</p>
            </div>

            <div className="space-y-2">
              <Label>Default Export Format</Label>
              <Select 
                value={formData.default_export_format}
                onValueChange={(v) => setFormData({...formData, default_export_format: v})}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select format" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="json">JSON</SelectItem>
                  <SelectItem value="csv">CSV</SelectItem>
                  <SelectItem value="pdf">PDF Report</SelectItem>
                  <SelectItem value="html">HTML Report</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Bell className="w-5 h-5 mr-2 text-primary" />
              Alerts
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>System Notifications</Label>
                <p className="text-sm text-muted-foreground">Receive UI alerts for important events.</p>
              </div>
              <Switch 
                checked={formData.notifications_enabled}
                onCheckedChange={(c) => setFormData({...formData, notifications_enabled: c})}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Key className="w-5 h-5 mr-2 text-primary" />
              API Access
            </CardTitle>
            <CardDescription>Your personal API key for automation</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex space-x-2">
              <Input 
                value={settings?.api_key || "********************************"} 
                readOnly 
                type="password"
                className="font-mono text-muted-foreground"
              />
              <Button variant="outline">Regenerate</Button>
            </div>
          </CardContent>
        </Card>
        
        <div className="flex justify-end">
          <Button onClick={handleSave} disabled={updateSettings.isPending} className="w-32">
            {updateSettings.isPending ? "Saving..." : (
              <>
                <Save className="w-4 h-4 mr-2" />
                Save All
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}
