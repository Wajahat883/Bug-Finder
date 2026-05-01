import { useState } from "react";
import { Shield, Eye, EyeOff, Mail, Lock, User, Zap, BarChart3, Brain, ArrowRight, CheckCircle2, Github } from "lucide-react";

const PLATFORM_FEATURES = [
  { icon: Brain, text: "AI-powered vulnerability analysis" },
  { icon: Zap, text: "Real-time scan streaming & alerts" },
  { icon: BarChart3, text: "Executive dashboards & OWASP coverage" },
  { icon: Shield, text: "CVSS scoring & SLA enforcement" },
];

export function AuthPage() {
  const [tab, setTab] = useState<"login" | "register">("login");
  const [showPass, setShowPass] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [username, setUsername] = useState("");

  return (
    <div className="min-h-screen bg-[#08080f] flex overflow-hidden">
      {/* Left panel — branding */}
      <div className="hidden lg:flex flex-col justify-between w-[42%] p-12 relative overflow-hidden bg-gradient-to-br from-[#0e0a1f] via-[#0d0d1f] to-[#080814]">
        {/* Ambient glows */}
        <div className="absolute top-0 left-0 w-80 h-80 rounded-full bg-violet-600/15 blur-[100px] pointer-events-none" />
        <div className="absolute bottom-0 right-0 w-64 h-64 rounded-full bg-cyan-500/8 blur-[80px] pointer-events-none" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[400px] h-[400px] rounded-full bg-violet-900/10 blur-[120px] pointer-events-none" />

        {/* Logo */}
        <div className="relative z-10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-violet-600 flex items-center justify-center shadow-lg shadow-violet-500/30">
              <Shield size={20} className="text-white" />
            </div>
            <div>
              <div className="font-bold text-lg text-white leading-none">Bug Finder Pro</div>
              <div className="text-xs text-violet-400/70 mt-0.5">Security Operations Platform</div>
            </div>
          </div>
        </div>

        {/* Center content */}
        <div className="relative z-10 space-y-10">
          <div>
            <h2 className="text-4xl font-black text-white leading-tight mb-4">
              Detect threats.<br />
              <span className="bg-gradient-to-r from-violet-400 to-cyan-400 bg-clip-text text-transparent">
                Remediate faster.
              </span>
            </h2>
            <p className="text-white/40 text-sm leading-relaxed max-w-xs">
              AI-powered security scanning that finds what automated tools miss, 
              then tells you exactly how to fix it.
            </p>
          </div>

          <div className="space-y-3">
            {PLATFORM_FEATURES.map(f => (
              <div key={f.text} className="flex items-center gap-3 group">
                <div className="w-8 h-8 rounded-lg bg-white/4 border border-white/6 flex items-center justify-center shrink-0 group-hover:border-violet-500/30 group-hover:bg-violet-500/10 transition-all">
                  <f.icon size={15} className="text-violet-400" />
                </div>
                <span className="text-sm text-white/50 group-hover:text-white/70 transition-colors">{f.text}</span>
              </div>
            ))}
          </div>

          {/* Scan preview card */}
          <div className="rounded-2xl border border-white/6 bg-white/2 p-4 backdrop-blur-sm">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                <span className="text-xs text-white/50 font-mono">Scan Active</span>
              </div>
              <span className="text-xs text-violet-400 font-mono">78%</span>
            </div>
            <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden mb-3">
              <div className="h-full bg-gradient-to-r from-violet-500 to-cyan-500 rounded-full" style={{ width: "78%" }} />
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 font-bold font-mono">CRIT</span>
                <span className="text-[10px] text-white/40 font-mono">SQL Injection — /api/login</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-400 font-bold font-mono">HIGH</span>
                <span className="text-[10px] text-white/40 font-mono">CORS Misconfiguration</span>
              </div>
            </div>
          </div>
        </div>

        <div className="relative z-10 text-xs text-white/20">
          © 2026 Bug Finder Pro
        </div>
      </div>

      {/* Right panel — form */}
      <div className="flex-1 flex items-center justify-center p-8 relative">
        {/* Subtle bg */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_rgba(139,92,246,0.04)_0%,_transparent_60%)] pointer-events-none" />

        <div className="w-full max-w-md relative z-10">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-2 mb-8">
            <div className="w-8 h-8 rounded-lg bg-violet-600 flex items-center justify-center">
              <Shield size={16} className="text-white" />
            </div>
            <span className="font-bold text-white">Bug Finder Pro</span>
          </div>

          {/* Tabs */}
          <div className="flex mb-8 bg-white/3 border border-white/6 rounded-xl p-1 gap-1">
            {(["login", "register"] as const).map(t => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`flex-1 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  tab === t
                    ? "bg-violet-600 text-white shadow-lg shadow-violet-500/20"
                    : "text-white/40 hover:text-white/70"
                }`}
              >
                {t === "login" ? "Sign In" : "Create Account"}
              </button>
            ))}
          </div>

          <div className="space-y-4">
            {tab === "login" ? (
              <>
                <div className="text-center mb-6">
                  <h1 className="text-2xl font-bold text-white mb-1">Welcome back</h1>
                  <p className="text-sm text-white/40">Sign in to your security dashboard</p>
                </div>

                {/* Email */}
                <div className="relative group">
                  <Mail size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-white/25 group-focus-within:text-violet-400 transition-colors" />
                  <input
                    type="email"
                    placeholder="you@example.com"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    className="w-full bg-white/4 border border-white/8 focus:border-violet-500/50 focus:bg-white/5 text-white placeholder-white/25 rounded-xl px-4 py-3.5 pl-10 text-sm outline-none transition-all"
                  />
                </div>

                {/* Password */}
                <div className="relative group">
                  <Lock size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-white/25 group-focus-within:text-violet-400 transition-colors" />
                  <input
                    type={showPass ? "text" : "password"}
                    placeholder="••••••••"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    className="w-full bg-white/4 border border-white/8 focus:border-violet-500/50 focus:bg-white/5 text-white placeholder-white/25 rounded-xl px-4 py-3.5 pl-10 pr-10 text-sm outline-none transition-all"
                  />
                  <button
                    onClick={() => setShowPass(!showPass)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-white/25 hover:text-white/60 transition-colors"
                  >
                    {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>

                <div className="flex items-center justify-end">
                  <button className="text-xs text-violet-400 hover:text-violet-300 transition-colors">Forgot password?</button>
                </div>

                <button className="w-full py-3.5 bg-violet-600 hover:bg-violet-500 text-white rounded-xl font-semibold transition-all shadow-lg shadow-violet-500/20 hover:shadow-violet-500/30 flex items-center justify-center gap-2 group">
                  Sign In
                  <ArrowRight size={16} className="group-hover:translate-x-0.5 transition-transform" />
                </button>

                <div className="flex items-center gap-3">
                  <div className="flex-1 h-px bg-white/6" />
                  <span className="text-xs text-white/25">or</span>
                  <div className="flex-1 h-px bg-white/6" />
                </div>

                <button className="w-full py-3.5 border border-white/10 hover:border-violet-500/30 hover:bg-violet-500/5 text-white/70 hover:text-white rounded-xl font-medium transition-all flex items-center justify-center gap-2.5 text-sm">
                  <Shield size={16} className="text-violet-400" />
                  Continue as Demo Admin
                </button>

                <p className="text-center text-xs text-white/25">
                  Demo: <span className="text-white/40 font-mono">demo@bugfinder.io</span> / <span className="text-white/40 font-mono">demo1234</span>
                </p>
              </>
            ) : (
              <>
                <div className="text-center mb-6">
                  <h1 className="text-2xl font-bold text-white mb-1">Create account</h1>
                  <p className="text-sm text-white/40">Start securing your applications today</p>
                </div>

                {/* Username */}
                <div className="relative group">
                  <User size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-white/25 group-focus-within:text-violet-400 transition-colors" />
                  <input
                    type="text"
                    placeholder="johndoe"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    className="w-full bg-white/4 border border-white/8 focus:border-violet-500/50 focus:bg-white/5 text-white placeholder-white/25 rounded-xl px-4 py-3.5 pl-10 text-sm outline-none transition-all"
                  />
                </div>

                {/* Email */}
                <div className="relative group">
                  <Mail size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-white/25 group-focus-within:text-violet-400 transition-colors" />
                  <input
                    type="email"
                    placeholder="you@example.com"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    className="w-full bg-white/4 border border-white/8 focus:border-violet-500/50 focus:bg-white/5 text-white placeholder-white/25 rounded-xl px-4 py-3.5 pl-10 text-sm outline-none transition-all"
                  />
                </div>

                {/* Password */}
                <div className="relative group">
                  <Lock size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-white/25 group-focus-within:text-violet-400 transition-colors" />
                  <input
                    type={showPass ? "text" : "password"}
                    placeholder="Min 6 characters"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    className="w-full bg-white/4 border border-white/8 focus:border-violet-500/50 focus:bg-white/5 text-white placeholder-white/25 rounded-xl px-4 py-3.5 pl-10 pr-10 text-sm outline-none transition-all"
                  />
                  <button
                    onClick={() => setShowPass(!showPass)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-white/25 hover:text-white/60 transition-colors"
                  >
                    {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>

                {/* Strength indicator */}
                {password.length > 0 && (
                  <div className="space-y-1">
                    <div className="flex gap-1">
                      {[...Array(4)].map((_, i) => (
                        <div key={i} className={`flex-1 h-1 rounded-full transition-all ${
                          password.length >= (i + 1) * 2
                            ? i < 1 ? "bg-red-500" : i < 2 ? "bg-orange-500" : i < 3 ? "bg-yellow-500" : "bg-green-500"
                            : "bg-white/10"
                        }`} />
                      ))}
                    </div>
                    <p className="text-[10px] text-white/30">
                      {password.length < 4 ? "Weak" : password.length < 6 ? "Fair" : password.length < 8 ? "Good" : "Strong"} password
                    </p>
                  </div>
                )}

                <button className="w-full py-3.5 bg-violet-600 hover:bg-violet-500 text-white rounded-xl font-semibold transition-all shadow-lg shadow-violet-500/20 flex items-center justify-center gap-2 group">
                  Create Account
                  <ArrowRight size={16} className="group-hover:translate-x-0.5 transition-transform" />
                </button>

                <p className="text-center text-xs text-white/25 leading-relaxed">
                  By creating an account you agree to our{" "}
                  <button className="text-violet-400 hover:text-violet-300 transition-colors">Terms</button>{" "}
                  and{" "}
                  <button className="text-violet-400 hover:text-violet-300 transition-colors">Privacy Policy</button>
                </p>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
