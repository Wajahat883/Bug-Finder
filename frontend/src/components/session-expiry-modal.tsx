/**
 * Session Expiry Modal — intercepts 401 responses globally and shows a
 * re-login prompt instead of silently redirecting or crashing.
 * Mount once inside AppLayout.
 */
import { useEffect, useState, useCallback } from "react";
import { useLocation } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Lock, Loader2, AlertTriangle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

// Global 401 event — fired by the fetch interceptor
export const SESSION_EXPIRED_EVENT = "session:expired";

let _interceptorInstalled = false;

/** Install once — patches global fetch to detect 401s */
export function installSessionInterceptor() {
  if (_interceptorInstalled || typeof window === "undefined") return;
  _interceptorInstalled = true;

  const originalFetch = window.fetch.bind(window);
  window.fetch = async (...args) => {
    const response = await originalFetch(...args);
    if (response.status === 401) {
      // Don't fire on the login endpoint itself
      const url = typeof args[0] === "string" ? args[0] : (args[0] as Request).url;
      const isAuthRoute = url.includes("/auth/login") || url.includes("/auth/me");
      if (!isAuthRoute) {
        window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
      }
    }
    return response;
  };
}

export function SessionExpiryModal() {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [, nav] = useLocation();
  const { toast } = useToast();

  useEffect(() => {
    installSessionInterceptor();
    const handler = () => setOpen(true);
    window.addEventListener(SESSION_EXPIRED_EVENT, handler);
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, handler);
  }, []);

  const handleReLogin = useCallback(async () => {
    if (!email || !password) { setError("Email and password are required"); return; }
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
        credentials: "include",
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({})) as { error?: string };
        throw new Error(body.error ?? "Invalid credentials");
      }
      setOpen(false);
      setPassword("");
      setEmail("");
      toast({ title: "Session restored", description: "You are logged back in." });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }, [email, password, toast]);

  const handleLogout = () => {
    setOpen(false);
    nav("/login");
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[200] flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <Card className="w-full max-w-sm border-yellow-500/30 shadow-2xl">
        <CardHeader className="text-center pb-4">
          <div className="mx-auto w-12 h-12 rounded-full bg-yellow-500/20 flex items-center justify-center mb-3">
            <Lock className="w-6 h-6 text-yellow-400" />
          </div>
          <CardTitle className="text-lg">Session Expired</CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            Your session has expired. Re-enter your credentials to continue — your work is safe.
          </p>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Email</label>
            <Input
              type="email"
              placeholder="your@email.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
              disabled={loading}
              autoFocus
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Password</label>
            <Input
              type="password"
              placeholder="••••••••••••"
              value={password}
              onChange={e => setPassword(e.target.value)}
              disabled={loading}
              onKeyDown={e => e.key === "Enter" && handleReLogin()}
            />
          </div>
          {error && (
            <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded px-3 py-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}
          <div className="flex gap-2 pt-1">
            <Button variant="outline" size="sm" className="flex-1" onClick={handleLogout} disabled={loading}>
              Go to Login
            </Button>
            <Button size="sm" className="flex-1" onClick={handleReLogin} disabled={loading}>
              {loading ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : null}
              {loading ? "Signing in…" : "Sign In"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
