import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { Shield, Lock, ArrowRight, Loader2, Eye, EyeOff, CheckCircle2, XCircle } from "lucide-react";

export default function ResetPassword() {
  const [, nav] = useLocation();
  const [token, setToken] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setToken(params.get("token") ?? "");
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) { setError("Passwords do not match"); return; }
    if (password.length < 6) { setError("Password must be at least 6 characters"); return; }
    setLoading(true); setError("");
    try {
      const r = await fetch("/api/auth/reset-password", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });
      const d = await r.json() as { error?: string };
      if (!r.ok) throw new Error(d.error ?? "Reset failed");
      setDone(true);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Reset failed");
    } finally { setLoading(false); }
  }

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: "#08080f" }}>
      <div className="w-full max-w-md p-8">
        <div className="flex items-center gap-2 mb-8">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: "#7c3aed" }}>
            <Shield size={16} className="text-white" />
          </div>
          <span className="font-bold text-white">Bug Finder Pro</span>
        </div>

        {done ? (
          <div className="text-center space-y-4">
            <div className="w-16 h-16 rounded-full flex items-center justify-center mx-auto" style={{ background: "rgba(34,197,94,0.1)" }}>
              <CheckCircle2 size={32} style={{ color: "#22c55e" }} />
            </div>
            <h1 className="text-2xl font-bold text-white">Password updated</h1>
            <p className="text-sm" style={{ color: "rgba(255,255,255,0.45)" }}>Your password has been reset successfully.</p>
            <button
              onClick={() => nav("/login")}
              className="w-full py-3.5 text-white rounded-xl font-semibold flex items-center justify-center gap-2 mt-4"
              style={{ background: "#7c3aed", boxShadow: "0 4px 20px rgba(124,58,237,0.3)" }}
            >
              Go to Login <ArrowRight size={16} />
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="mb-6">
              <h1 className="text-2xl font-bold text-white mb-1">Reset password</h1>
              <p className="text-sm" style={{ color: "rgba(255,255,255,0.38)" }}>Enter your new password below.</p>
            </div>

            {!token && (
              <div className="px-4 py-3 rounded-xl text-xs" style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", color: "#fca5a5" }}>
                Invalid or missing reset token. Please request a new password reset link.
              </div>
            )}

            {error && (
              <div className="px-4 py-3 rounded-xl text-xs" style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", color: "#fca5a5" }}>
                {error}
              </div>
            )}

            <div className="relative">
              <Lock size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "rgba(255,255,255,0.25)" }} />
              <input
                type={showPass ? "text" : "password"} required minLength={6} placeholder="New password"
                value={password} onChange={e => setPassword(e.target.value)}
                className="w-full rounded-xl pl-10 pr-10 px-4 py-3.5 text-sm outline-none"
                style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: "white" }}
              />
              <button type="button" onClick={() => setShowPass(!showPass)}
                className="absolute right-3.5 top-1/2 -translate-y-1/2" style={{ color: "rgba(255,255,255,0.25)" }}>
                {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>

            <div className="relative">
              <Lock size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "rgba(255,255,255,0.25)" }} />
              <input
                type={showPass ? "text" : "password"} required placeholder="Confirm new password"
                value={confirm} onChange={e => setConfirm(e.target.value)}
                className="w-full rounded-xl pl-10 pr-10 px-4 py-3.5 text-sm outline-none"
                style={{
                  background: "rgba(255,255,255,0.04)",
                  border: `1px solid ${confirm.length > 0 ? confirm === password ? "rgba(34,197,94,0.4)" : "rgba(239,68,68,0.4)" : "rgba(255,255,255,0.08)"}`,
                  color: "white",
                }}
              />
              {confirm.length > 0 && (
                <div className="absolute right-3.5 top-1/2 -translate-y-1/2">
                  {confirm === password ? <CheckCircle2 size={14} style={{ color: "#22c55e" }} /> : <XCircle size={14} style={{ color: "#ef4444" }} />}
                </div>
              )}
            </div>

            <button
              type="submit" disabled={loading || !token}
              className="w-full py-3.5 text-white rounded-xl font-semibold flex items-center justify-center gap-2 disabled:opacity-60"
              style={{ background: "#7c3aed", boxShadow: "0 4px 20px rgba(124,58,237,0.3)" }}
            >
              {loading ? <Loader2 size={16} className="animate-spin" /> : <>Set New Password <ArrowRight size={16} /></>}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
