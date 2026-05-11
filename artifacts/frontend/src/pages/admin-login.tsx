import { useState } from "react";
import { useLocation } from "wouter";
import { Shield, Lock, Mail, ArrowRight, Loader2, Eye, EyeOff, AlertTriangle } from "lucide-react";

const API = "/api";

export default function AdminLogin() {
  const [, nav] = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const r = await fetch(`${API}/auth/login`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "Login failed");
      if (d.role !== "admin") {
        await fetch(`${API}/auth/logout`, { method: "POST", credentials: "include" });
        throw new Error("Access denied — admin credentials required");
      }
      nav("/admin/users");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center p-6"
      style={{ background: "linear-gradient(135deg, #050508 0%, #0a0a14 50%, #06060f 100%)" }}
    >
      {/* Background glow */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-96 h-96 rounded-full"
          style={{ background: "rgba(220,38,38,0.06)", filter: "blur(120px)" }} />
        <div className="absolute bottom-1/4 left-1/2 -translate-x-1/2 w-64 h-64 rounded-full"
          style={{ background: "rgba(124,58,237,0.05)", filter: "blur(100px)" }} />
      </div>

      <div className="relative z-10 w-full max-w-sm">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl mb-4"
            style={{ background: "linear-gradient(135deg, #7f1d1d, #dc2626)", boxShadow: "0 0 32px rgba(220,38,38,0.3)" }}>
            <Shield className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white mb-1">Admin Portal</h1>
          <p className="text-sm" style={{ color: "rgba(255,255,255,0.35)" }}>
            Restricted access — authorised personnel only
          </p>
        </div>

        {/* Warning banner */}
        <div className="flex items-start gap-2.5 mb-6 px-3.5 py-3 rounded-xl"
          style={{ background: "rgba(220,38,38,0.08)", border: "1px solid rgba(220,38,38,0.2)" }}>
          <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" style={{ color: "#f87171" }} />
          <p className="text-xs leading-relaxed" style={{ color: "rgba(248,113,113,0.85)" }}>
            All admin actions are logged and audited. Unauthorised access attempts are reported.
          </p>
        </div>

        {/* Form card */}
        <div className="rounded-2xl p-6 space-y-4"
          style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)" }}>

          {error && (
            <div className="px-3.5 py-3 rounded-xl text-xs"
              style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", color: "#fca5a5" }}>
              {error}
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-3.5">
            <div className="relative">
              <Mail size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
                style={{ color: "rgba(255,255,255,0.25)" }} />
              <input
                type="email"
                required
                placeholder="Admin email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                className="w-full rounded-xl pl-10 pr-4 py-3.5 text-sm outline-none transition-all"
                style={{
                  background: "rgba(255,255,255,0.04)",
                  border: "1px solid rgba(255,255,255,0.08)",
                  color: "white",
                }}
                onFocus={e => (e.target.style.borderColor = "rgba(220,38,38,0.5)")}
                onBlur={e => (e.target.style.borderColor = "rgba(255,255,255,0.08)")}
              />
            </div>

            <div className="relative">
              <Lock size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
                style={{ color: "rgba(255,255,255,0.25)" }} />
              <input
                type={showPass ? "text" : "password"}
                required
                placeholder="Admin password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="w-full rounded-xl pl-10 pr-10 py-3.5 text-sm outline-none transition-all"
                style={{
                  background: "rgba(255,255,255,0.04)",
                  border: "1px solid rgba(255,255,255,0.08)",
                  color: "white",
                }}
                onFocus={e => (e.target.style.borderColor = "rgba(220,38,38,0.5)")}
                onBlur={e => (e.target.style.borderColor = "rgba(255,255,255,0.08)")}
              />
              <button
                type="button"
                onClick={() => setShowPass(!showPass)}
                className="absolute right-3.5 top-1/2 -translate-y-1/2 transition-opacity hover:opacity-80"
                style={{ color: "rgba(255,255,255,0.25)" }}
              >
                {showPass ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3.5 text-white rounded-xl font-semibold transition-all flex items-center justify-center gap-2 disabled:opacity-60 mt-1"
              style={{ background: "linear-gradient(135deg, #991b1b, #dc2626)", boxShadow: "0 4px 20px rgba(220,38,38,0.25)" }}
            >
              {loading
                ? <Loader2 size={16} className="animate-spin" />
                : <><Lock size={15} /> Authenticate <ArrowRight size={15} /></>}
            </button>
          </form>
        </div>

        {/* Back to user login */}
        <p className="text-center mt-5 text-xs" style={{ color: "rgba(255,255,255,0.2)" }}>
          Not an admin?{" "}
          <button
            onClick={() => nav("/login")}
            className="hover:opacity-80 transition-opacity"
            style={{ color: "rgba(255,255,255,0.45)" }}
          >
            Go to User Login →
          </button>
        </p>

        <p className="text-center mt-3 text-[11px]" style={{ color: "rgba(255,255,255,0.12)" }}>
          Bug Finder Pro · Admin Portal · Restricted
        </p>
      </div>
    </div>
  );
}
