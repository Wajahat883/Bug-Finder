import { useState } from "react";
import { useLocation } from "wouter";
import { Shield, Eye, EyeOff, Mail, Lock, User, Zap, BarChart3, Brain, ArrowRight, Loader2, CheckCircle2, XCircle } from "lucide-react";

const API = "/api";

const PLATFORM_FEATURES = [
  { icon: Brain, text: "AI-powered vulnerability analysis" },
  { icon: Zap, text: "Real-time scan streaming & alerts" },
  { icon: BarChart3, text: "Executive dashboards & OWASP coverage" },
  { icon: Shield, text: "CVSS scoring & SLA enforcement" },
];

export default function Login() {
  const [, nav] = useLocation();
  const [tab, setTab] = useState<"login" | "register">("login");
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [showConfirm, setShowConfirm] = useState(false);
  const [loginForm, setLoginForm] = useState({ email: "", password: "" });
  const [regForm, setRegForm] = useState({ firstName: "", lastName: "", email: "", password: "", confirmPassword: "" });

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true); setError("");
    try {
      const r = await fetch(`${API}/auth/login`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(loginForm),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "Login failed");
      nav("/dashboard");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally { setLoading(false); }
  }

  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    if (regForm.password !== regForm.confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    setLoading(true); setError("");
    try {
      const r = await fetch(`${API}/auth/register`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          firstName: regForm.firstName,
          lastName: regForm.lastName,
          email: regForm.email,
          password: regForm.password,
        }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "Registration failed");
      nav("/dashboard");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally { setLoading(false); }
  }

  async function handleDemo() {
    setLoading(true); setError("");
    try {
      const r = await fetch(`${API}/auth/demo`, { method: "POST", credentials: "include" });
      if (!r.ok) throw new Error("Demo login failed");
      nav("/dashboard");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Demo failed");
    } finally { setLoading(false); }
  }

  const strength = regForm.password.length === 0 ? 0
    : regForm.password.length < 4 ? 1
    : regForm.password.length < 6 ? 2
    : regForm.password.length < 8 ? 3 : 4;

  const strengthLabel = ["", "Weak", "Fair", "Good", "Strong"][strength];
  const strengthColor = ["", "#ef4444", "#f97316", "#eab308", "#22c55e"][strength];

  return (
    <div className="min-h-screen flex overflow-hidden" style={{ background: "#08080f", color: "white" }}>
      {/* Left branding panel */}
      <div className="hidden lg:flex flex-col justify-between w-[42%] p-12 relative overflow-hidden"
        style={{ background: "linear-gradient(135deg, #0e0a1f 0%, #0d0d1f 50%, #080814 100%)" }}>
        <div className="absolute top-0 left-0 w-80 h-80 rounded-full pointer-events-none" style={{ background: "rgba(124,58,237,0.12)", filter: "blur(100px)" }} />
        <div className="absolute bottom-0 right-0 w-64 h-64 rounded-full pointer-events-none" style={{ background: "rgba(6,182,212,0.06)", filter: "blur(80px)" }} />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 rounded-full pointer-events-none" style={{ background: "rgba(109,40,217,0.08)", filter: "blur(120px)" }} />

        {/* Logo */}
        <div className="relative z-10">
          <button onClick={() => nav("/")} className="flex items-center gap-3 hover:opacity-80 transition-opacity">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: "#7c3aed", boxShadow: "0 0 20px rgba(124,58,237,0.4)" }}>
              <Shield size={20} className="text-white" />
            </div>
            <div>
              <div className="font-bold text-lg text-white leading-none">Bug Finder Pro</div>
              <div className="text-xs mt-0.5" style={{ color: "rgba(167,139,250,0.7)" }}>Security Operations Platform</div>
            </div>
          </button>
        </div>

        {/* Center */}
        <div className="relative z-10 space-y-10">
          <div>
            <h2 className="text-4xl font-black text-white leading-tight mb-4">
              Detect threats.<br />
              <span style={{ background: "linear-gradient(90deg, #a78bfa, #67e8f9)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
                Remediate faster.
              </span>
            </h2>
            <p className="text-sm leading-relaxed max-w-xs" style={{ color: "rgba(255,255,255,0.38)" }}>
              AI-powered security scanning that finds what automated tools miss,
              then tells you exactly how to fix it.
            </p>
          </div>
          <div className="space-y-3">
            {PLATFORM_FEATURES.map(f => (
              <div key={f.text} className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0" style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.06)" }}>
                  <f.icon size={15} style={{ color: "#a78bfa" }} />
                </div>
                <span className="text-sm" style={{ color: "rgba(255,255,255,0.45)" }}>{f.text}</span>
              </div>
            ))}
          </div>

          {/* Mini scan card */}
          <div className="rounded-2xl p-4 backdrop-blur-sm" style={{ border: "1px solid rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.02)" }}>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full animate-pulse" style={{ background: "#4ade80" }} />
                <span className="text-xs font-mono" style={{ color: "rgba(255,255,255,0.45)" }}>Scan Active</span>
              </div>
              <span className="text-xs font-mono" style={{ color: "#a78bfa" }}>78%</span>
            </div>
            <div className="w-full h-1.5 rounded-full mb-3" style={{ background: "rgba(255,255,255,0.05)" }}>
              <div className="h-full rounded-full" style={{ width: "78%", background: "linear-gradient(90deg, #7c3aed, #06b6d4)" }} />
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-[10px] px-1.5 py-0.5 rounded font-bold font-mono" style={{ background: "rgba(239,68,68,0.2)", color: "#f87171" }}>CRIT</span>
                <span className="text-[10px] font-mono" style={{ color: "rgba(255,255,255,0.35)" }}>SQL Injection — /api/login</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] px-1.5 py-0.5 rounded font-bold font-mono" style={{ background: "rgba(249,115,22,0.2)", color: "#fb923c" }}>HIGH</span>
                <span className="text-[10px] font-mono" style={{ color: "rgba(255,255,255,0.35)" }}>CORS Misconfiguration</span>
              </div>
            </div>
          </div>
        </div>

        <div className="relative z-10 text-xs" style={{ color: "rgba(255,255,255,0.18)" }}>© 2026 Bug Finder Pro</div>
      </div>

      {/* Right form panel */}
      <div className="flex-1 flex items-center justify-center p-8 relative">
        <div className="absolute inset-0 pointer-events-none" style={{ background: "radial-gradient(ellipse at top right, rgba(139,92,246,0.04) 0%, transparent 60%)" }} />

        <div className="w-full max-w-md relative z-10">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-2 mb-8">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: "#7c3aed" }}>
              <Shield size={16} className="text-white" />
            </div>
            <span className="font-bold text-white">Bug Finder Pro</span>
          </div>

          {/* Tabs */}
          <div className="flex mb-8 p-1 gap-1 rounded-xl" style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)" }}>
            {(["login", "register"] as const).map(t => (
              <button
                key={t}
                onClick={() => { setTab(t); setError(""); }}
                className="flex-1 py-2.5 rounded-lg text-sm font-medium transition-all"
                style={tab === t
                  ? { background: "#7c3aed", color: "white", boxShadow: "0 4px 15px rgba(124,58,237,0.3)" }
                  : { color: "rgba(255,255,255,0.38)" }}
              >
                {t === "login" ? "Sign In" : "Create Account"}
              </button>
            ))}
          </div>

          {error && (
            <div className="mb-4 px-4 py-3 rounded-xl text-xs" style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", color: "#fca5a5" }}>
              {error}
            </div>
          )}

          {tab === "login" ? (
            <form onSubmit={handleLogin} className="space-y-4">
              <div className="text-center mb-6">
                <h1 className="text-2xl font-bold text-white mb-1">Welcome back</h1>
                <p className="text-sm" style={{ color: "rgba(255,255,255,0.38)" }}>Sign in to your security dashboard</p>
              </div>

              <div className="relative">
                <Mail size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "rgba(255,255,255,0.25)" }} />
                <input
                  type="email" required placeholder="you@example.com"
                  value={loginForm.email} onChange={e => setLoginForm(p => ({ ...p, email: e.target.value }))}
                  className="w-full rounded-xl pl-10 px-4 py-3.5 text-sm outline-none transition-all"
                  style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: "white" }}
                />
              </div>

              <div className="relative">
                <Lock size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "rgba(255,255,255,0.25)" }} />
                <input
                  type={showPass ? "text" : "password"} required placeholder="••••••••"
                  value={loginForm.password} onChange={e => setLoginForm(p => ({ ...p, password: e.target.value }))}
                  className="w-full rounded-xl pl-10 pr-10 px-4 py-3.5 text-sm outline-none transition-all"
                  style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: "white" }}
                />
                <button type="button" onClick={() => setShowPass(!showPass)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 transition-opacity hover:opacity-80"
                  style={{ color: "rgba(255,255,255,0.25)" }}>
                  {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>

              <button
                type="submit" disabled={loading}
                className="w-full py-3.5 text-white rounded-xl font-semibold transition-all flex items-center justify-center gap-2 group disabled:opacity-60"
                style={{ background: "#7c3aed", boxShadow: "0 4px 20px rgba(124,58,237,0.3)" }}
              >
                {loading ? <Loader2 size={16} className="animate-spin" /> : <>Sign In <ArrowRight size={16} /></>}
              </button>

              <div className="flex items-center gap-3">
                <div className="flex-1 h-px" style={{ background: "rgba(255,255,255,0.06)" }} />
                <span className="text-xs" style={{ color: "rgba(255,255,255,0.22)" }}>or</span>
                <div className="flex-1 h-px" style={{ background: "rgba(255,255,255,0.06)" }} />
              </div>

              <button
                type="button" onClick={handleDemo} disabled={loading}
                className="w-full py-3.5 rounded-xl font-medium text-sm transition-all flex items-center justify-center gap-2.5 disabled:opacity-60"
                style={{ border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.6)" }}
              >
                {loading ? <Loader2 size={16} className="animate-spin" /> : <Shield size={16} style={{ color: "#a78bfa" }} />}
                Continue as Demo Admin
              </button>

              <p className="text-center text-xs" style={{ color: "rgba(255,255,255,0.22)" }}>
                Demo: <span className="font-mono" style={{ color: "rgba(255,255,255,0.38)" }}>demo@bugfinder.io</span> / <span className="font-mono" style={{ color: "rgba(255,255,255,0.38)" }}>demo1234</span>
              </p>
            </form>
          ) : (
            <form onSubmit={handleRegister} className="space-y-3">
              <div className="text-center mb-5">
                <h1 className="text-2xl font-bold text-white mb-1">Create account</h1>
                <p className="text-sm" style={{ color: "rgba(255,255,255,0.38)" }}>Start securing your applications today</p>
              </div>

              {/* First name + Last name side by side */}
              <div className="grid grid-cols-2 gap-3">
                <div className="relative">
                  <User size={14} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "rgba(255,255,255,0.25)" }} />
                  <input
                    type="text" required placeholder="First name"
                    value={regForm.firstName} onChange={e => setRegForm(p => ({ ...p, firstName: e.target.value }))}
                    className="w-full rounded-xl pl-9 pr-3 py-3 text-sm outline-none transition-all"
                    style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: "white" }}
                  />
                </div>
                <div className="relative">
                  <User size={14} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "rgba(255,255,255,0.25)" }} />
                  <input
                    type="text" required placeholder="Last name"
                    value={regForm.lastName} onChange={e => setRegForm(p => ({ ...p, lastName: e.target.value }))}
                    className="w-full rounded-xl pl-9 pr-3 py-3 text-sm outline-none transition-all"
                    style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: "white" }}
                  />
                </div>
              </div>

              {/* Email */}
              <div className="relative">
                <Mail size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "rgba(255,255,255,0.25)" }} />
                <input
                  type="email" required placeholder="Email address"
                  value={regForm.email} onChange={e => setRegForm(p => ({ ...p, email: e.target.value }))}
                  className="w-full rounded-xl pl-10 px-4 py-3 text-sm outline-none transition-all"
                  style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: "white" }}
                />
              </div>

              {/* Password */}
              <div className="relative">
                <Lock size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "rgba(255,255,255,0.25)" }} />
                <input
                  type={showPass ? "text" : "password"} required minLength={6} placeholder="Password (min 6 characters)"
                  value={regForm.password} onChange={e => setRegForm(p => ({ ...p, password: e.target.value }))}
                  className="w-full rounded-xl pl-10 pr-10 py-3 text-sm outline-none transition-all"
                  style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: "white" }}
                />
                <button type="button" onClick={() => setShowPass(!showPass)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 transition-opacity hover:opacity-80"
                  style={{ color: "rgba(255,255,255,0.25)" }}>
                  {showPass ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>

              {/* Strength meter */}
              {regForm.password.length > 0 && (
                <div className="space-y-1">
                  <div className="flex gap-1">
                    {[...Array(4)].map((_, i) => (
                      <div key={i} className="flex-1 h-1 rounded-full transition-all"
                        style={{ background: i < strength ? strengthColor : "rgba(255,255,255,0.08)" }} />
                    ))}
                  </div>
                  <p className="text-[10px]" style={{ color: "rgba(255,255,255,0.3)" }}>{strengthLabel} password</p>
                </div>
              )}

              {/* Confirm password */}
              <div className="relative">
                <Lock size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "rgba(255,255,255,0.25)" }} />
                <input
                  type={showConfirm ? "text" : "password"} required placeholder="Confirm password"
                  value={regForm.confirmPassword} onChange={e => setRegForm(p => ({ ...p, confirmPassword: e.target.value }))}
                  className="w-full rounded-xl pl-10 pr-10 py-3 text-sm outline-none transition-all"
                  style={{
                    background: "rgba(255,255,255,0.04)",
                    border: `1px solid ${regForm.confirmPassword.length > 0
                      ? regForm.confirmPassword === regForm.password ? "rgba(34,197,94,0.4)" : "rgba(239,68,68,0.4)"
                      : "rgba(255,255,255,0.08)"}`,
                    color: "white",
                  }}
                />
                <button type="button" onClick={() => setShowConfirm(!showConfirm)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 transition-opacity hover:opacity-80"
                  style={{ color: "rgba(255,255,255,0.25)" }}>
                  {showConfirm ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
                {regForm.confirmPassword.length > 0 && (
                  <div className="absolute right-10 top-1/2 -translate-y-1/2">
                    {regForm.confirmPassword === regForm.password
                      ? <CheckCircle2 size={14} style={{ color: "#22c55e" }} />
                      : <XCircle size={14} style={{ color: "#ef4444" }} />}
                  </div>
                )}
              </div>

              <button
                type="submit" disabled={loading}
                className="w-full py-3.5 text-white rounded-xl font-semibold transition-all flex items-center justify-center gap-2 disabled:opacity-60"
                style={{ background: "#7c3aed", boxShadow: "0 4px 20px rgba(124,58,237,0.3)" }}
              >
                {loading ? <Loader2 size={16} className="animate-spin" /> : <>Create Account <ArrowRight size={16} /></>}
              </button>

              <p className="text-center text-xs leading-relaxed" style={{ color: "rgba(255,255,255,0.22)" }}>
                By creating an account you agree to our{" "}
                <span className="cursor-pointer hover:opacity-80" style={{ color: "#a78bfa" }}>Terms</span>{" "}
                and{" "}
                <span className="cursor-pointer hover:opacity-80" style={{ color: "#a78bfa" }}>Privacy Policy</span>
              </p>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
