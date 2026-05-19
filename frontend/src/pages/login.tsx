import { useState } from "react";
import { useLocation } from "wouter";
import { Shield, Eye, EyeOff, Mail, Lock, User, Zap, BarChart3, Brain, ArrowRight, Loader2, CheckCircle2, XCircle } from "lucide-react";

function GithubIcon() {
  return (
    <svg viewBox="0 0 24 24" className="w-4 h-4 fill-current">
      <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
    </svg>
  );
}

function GoogleIcon() {
  return (
    <svg viewBox="0 0 24 24" className="w-4 h-4">
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
    </svg>
  );
}

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
  const [loginForm, setLoginForm] = useState({ email: "", password: "", rememberMe: false });
  const [regForm, setRegForm] = useState({ firstName: "", lastName: "", email: "", password: "", confirmPassword: "" });

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true); setError("");
    try {
      const r = await fetch(`${API}/auth/login`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: loginForm.email, password: loginForm.password, remember_me: loginForm.rememberMe }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "Login failed");
      nav(d.role === "admin" ? "/admin/panel" : "/dashboard");
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

const pwVal = regForm.password;
  const pwHasUpper = /[A-Z]/.test(pwVal);
  const pwHasNumber = /[0-9]/.test(pwVal);
  const pwHasSpecial = /[^A-Za-z0-9]/.test(pwVal);
  const pwLongEnough = pwVal.length >= 12;
  const strength = pwVal.length === 0 ? 0
    : [pwLongEnough, pwHasUpper, pwHasNumber, pwHasSpecial].filter(Boolean).length;

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

              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input type="checkbox" checked={loginForm.rememberMe}
                  onChange={e => setLoginForm(p => ({ ...p, rememberMe: e.target.checked }))}
                  className="w-4 h-4 rounded accent-purple-600 cursor-pointer" />
                <span className="text-xs" style={{ color: "rgba(255,255,255,0.38)" }}>Keep me signed in for 30 days</span>
              </label>

              <button
                type="submit" disabled={loading}
                className="w-full py-3.5 text-white rounded-xl font-semibold transition-all flex items-center justify-center gap-2 group disabled:opacity-60"
                style={{ background: "#7c3aed", boxShadow: "0 4px 20px rgba(124,58,237,0.3)" }}
              >
                {loading ? <Loader2 size={16} className="animate-spin" /> : <>Sign In <ArrowRight size={16} /></>}
              </button>

              <div className="text-right">
                <a href="/forgot-password" className="text-xs hover:opacity-80" style={{ color: "#a78bfa" }}>Forgot password?</a>
              </div>
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
                  type={showPass ? "text" : "password"} required minLength={12} placeholder="Password (min 12 chars, A-Z, 0-9, symbol)"
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
                  <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-0.5">
                    <p className="text-[10px]" style={{ color: strengthColor || "rgba(255,255,255,0.3)" }}>{strengthLabel} password</p>
                    {!pwLongEnough && <p className="text-[10px]" style={{ color: "rgba(255,255,255,0.3)" }}>12+ chars</p>}
                    {!pwHasUpper && <p className="text-[10px]" style={{ color: "rgba(255,255,255,0.3)" }}>uppercase</p>}
                    {!pwHasNumber && <p className="text-[10px]" style={{ color: "rgba(255,255,255,0.3)" }}>number</p>}
                    {!pwHasSpecial && <p className="text-[10px]" style={{ color: "rgba(255,255,255,0.3)" }}>symbol</p>}
                  </div>
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
