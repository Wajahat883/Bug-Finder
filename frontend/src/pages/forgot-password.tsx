import { useState } from "react";
import { useLocation } from "wouter";
import { Shield, Mail, ArrowRight, Loader2, ArrowLeft, CheckCircle2 } from "lucide-react";

export default function ForgotPassword() {
  const [, nav] = useLocation();
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true); setError("");
    try {
      await fetch("/api/auth/forgot-password", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      // Always show success to prevent user enumeration
      setSent(true);
    } catch {
      setError("An error occurred. Please try again.");
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

        {sent ? (
          <div className="text-center space-y-4">
            <div className="w-16 h-16 rounded-full flex items-center justify-center mx-auto" style={{ background: "rgba(34,197,94,0.1)" }}>
              <CheckCircle2 size={32} style={{ color: "#22c55e" }} />
            </div>
            <h1 className="text-2xl font-bold text-white">Check your email</h1>
            <p className="text-sm" style={{ color: "rgba(255,255,255,0.45)" }}>
              If an account exists for <strong className="text-white">{email}</strong>, a password reset link has been sent.
            </p>
            <p className="text-xs" style={{ color: "rgba(255,255,255,0.3)" }}>The link expires in 1 hour.</p>
            <button onClick={() => nav("/login")} className="text-sm mt-4 flex items-center gap-1 mx-auto hover:opacity-80" style={{ color: "#a78bfa" }}>
              <ArrowLeft size={14} /> Back to login
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="mb-6">
              <h1 className="text-2xl font-bold text-white mb-1">Forgot password?</h1>
              <p className="text-sm" style={{ color: "rgba(255,255,255,0.38)" }}>Enter your email and we'll send a reset link.</p>
            </div>

            {error && (
              <div className="px-4 py-3 rounded-xl text-xs" style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", color: "#fca5a5" }}>
                {error}
              </div>
            )}

            <div className="relative">
              <Mail size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "rgba(255,255,255,0.25)" }} />
              <input
                type="email" required placeholder="you@example.com"
                value={email} onChange={e => setEmail(e.target.value)}
                className="w-full rounded-xl pl-10 px-4 py-3.5 text-sm outline-none"
                style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: "white" }}
              />
            </div>

            <button
              type="submit" disabled={loading}
              className="w-full py-3.5 text-white rounded-xl font-semibold flex items-center justify-center gap-2 disabled:opacity-60"
              style={{ background: "#7c3aed", boxShadow: "0 4px 20px rgba(124,58,237,0.3)" }}
            >
              {loading ? <Loader2 size={16} className="animate-spin" /> : <>Send Reset Link <ArrowRight size={16} /></>}
            </button>

            <button type="button" onClick={() => nav("/login")} className="w-full text-sm flex items-center justify-center gap-1 mt-2 hover:opacity-80" style={{ color: "rgba(255,255,255,0.38)" }}>
              <ArrowLeft size={14} /> Back to login
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
