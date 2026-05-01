import { useState } from "react";
import { Shield, Zap, Brain, GitBranch, BarChart3, Lock, ChevronRight, Terminal, AlertTriangle, CheckCircle2, Activity, Globe, ArrowRight, Star } from "lucide-react";

const FEATURES = [
  { icon: Brain, title: "AI-Powered Analysis", desc: "Claude streams real-time executive summaries and remediation advice for every finding, tailored to your stack.", color: "#8b5cf6" },
  { icon: Zap, title: "Live Scan Streaming", desc: "Watch vulnerabilities appear as they're discovered with SSE-powered real-time progress and finding feeds.", color: "#06b6d4" },
  { icon: Shield, title: "CVSS 3.1 Scoring", desc: "Interactive CVSS calculator with automatic severity classification — Critical, High, Medium, Low, Info.", color: "#10b981" },
  { icon: GitBranch, title: "GitHub Integration", desc: "One-click issue creation for any finding directly into your repo with full context and remediation steps.", color: "#f59e0b" },
  { icon: BarChart3, title: "Executive Dashboard", desc: "Board-ready risk posture charts, OWASP Top 10 heatmaps, and attack surface topology graphs.", color: "#ef4444" },
  { icon: Lock, title: "SLA Enforcement", desc: "Automatic deadline tracking — Critical: 24h, High: 72h, Medium: 7d — with color-coded urgency alerts.", color: "#ec4899" },
];

const OWASP = [
  "A01: Broken Access Control",
  "A02: Cryptographic Failures",
  "A03: Injection",
  "A04: Insecure Design",
  "A05: Security Misconfiguration",
  "A06: Vulnerable Components",
  "A07: Auth Failures",
  "A08: Data Integrity Failures",
  "A09: Logging Failures",
  "A10: SSRF",
];

const STATS = [
  { value: "112+", label: "Vulnerabilities Detected" },
  { value: "18", label: "Scans Completed" },
  { value: "5", label: "Targets Monitored" },
  { value: "100", label: "Risk Score Tracked" },
];

export function LandingPage() {
  const [hoveredFeature, setHoveredFeature] = useState<number | null>(null);

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-white font-sans overflow-x-hidden">
      {/* Nav */}
      <nav className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-8 py-4 border-b border-white/5 backdrop-blur-xl bg-[#0a0a0f]/80">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-violet-600 flex items-center justify-center shadow-lg shadow-violet-500/30">
            <Shield className="w-4.5 h-4.5 text-white" size={18} />
          </div>
          <span className="font-bold text-lg tracking-tight">Bug Finder <span className="text-violet-400">Pro</span></span>
        </div>
        <div className="hidden md:flex items-center gap-6 text-sm text-white/60">
          <a href="#features" className="hover:text-white transition-colors">Features</a>
          <a href="#owasp" className="hover:text-white transition-colors">OWASP</a>
          <a href="#stats" className="hover:text-white transition-colors">Coverage</a>
        </div>
        <div className="flex items-center gap-3">
          <button className="px-4 py-2 text-sm text-white/70 hover:text-white transition-colors">Sign In</button>
          <button className="px-4 py-2 text-sm bg-violet-600 hover:bg-violet-500 text-white rounded-lg font-medium transition-all shadow-lg shadow-violet-500/20 hover:shadow-violet-500/40">
            Start Free Scan
          </button>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative pt-32 pb-24 px-8 text-center overflow-hidden">
        {/* Background glow */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="w-[600px] h-[600px] rounded-full bg-violet-600/10 blur-[120px]" />
        </div>
        <div className="absolute top-20 left-1/4 w-72 h-72 rounded-full bg-cyan-500/5 blur-[100px] pointer-events-none" />
        <div className="absolute top-40 right-1/4 w-48 h-48 rounded-full bg-pink-500/5 blur-[80px] pointer-events-none" />

        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-violet-500/30 bg-violet-500/10 text-xs text-violet-300 font-medium mb-6">
          <div className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse" />
          AI-Powered Security Operations Platform
        </div>

        <h1 className="text-5xl md:text-7xl font-black tracking-tight mb-6 leading-none">
          Find Bugs.{" "}
          <span className="bg-gradient-to-r from-violet-400 via-cyan-400 to-violet-400 bg-clip-text text-transparent">
            Before They Find You.
          </span>
        </h1>
        <p className="text-lg text-white/50 max-w-2xl mx-auto mb-10 leading-relaxed">
          Enterprise-grade vulnerability scanning with real-time AI analysis, OWASP Top 10 coverage, 
          SLA enforcement, and one-click GitHub issue creation — all in one platform.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <button className="group flex items-center gap-2 px-6 py-3.5 bg-violet-600 hover:bg-violet-500 text-white rounded-xl font-semibold transition-all shadow-xl shadow-violet-500/25 hover:shadow-violet-500/40 hover:-translate-y-0.5">
            Launch Your First Scan
            <ArrowRight size={16} className="group-hover:translate-x-0.5 transition-transform" />
          </button>
          <button className="flex items-center gap-2 px-6 py-3.5 border border-white/10 hover:border-white/20 text-white/70 hover:text-white rounded-xl font-medium transition-all hover:bg-white/5">
            <Terminal size={16} />
            Continue as Demo
          </button>
        </div>

        {/* Terminal preview */}
        <div className="mt-16 max-w-3xl mx-auto rounded-2xl border border-white/8 bg-[#0f0f1a] overflow-hidden shadow-2xl shadow-black/50 text-left">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-white/5 bg-white/2">
            <div className="w-3 h-3 rounded-full bg-red-500/70" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/70" />
            <div className="w-3 h-3 rounded-full bg-green-500/70" />
            <span className="ml-2 text-xs text-white/30 font-mono">bug-finder-pro — scan engine</span>
          </div>
          <div className="p-5 font-mono text-xs space-y-1.5">
            <p><span className="text-green-400">✓</span> <span className="text-white/50">TLS/SSL Certificate Check</span> <span className="text-white/20">— Pass</span></p>
            <p><span className="text-green-400">✓</span> <span className="text-white/50">Security Headers Analysis</span> <span className="text-white/20">— 3 issues found</span></p>
            <p><span className="text-yellow-400">⚠</span> <span className="text-yellow-300">CORS Policy Misconfiguration</span> <span className="text-yellow-400/60">— HIGH</span></p>
            <p><span className="text-red-400">✗</span> <span className="text-red-300">SQL Injection in /api/users</span> <span className="text-red-400/60">— CRITICAL</span></p>
            <p><span className="text-red-400">✗</span> <span className="text-red-300">JWT Weak Signing Secret</span> <span className="text-red-400/60">— CRITICAL</span></p>
            <p><span className="text-cyan-400">›</span> <span className="text-white/30">AI Summary generating</span><span className="text-cyan-400 animate-pulse">...</span></p>
          </div>
        </div>
      </section>

      {/* Stats */}
      <section id="stats" className="py-16 px-8 border-y border-white/5">
        <div className="max-w-4xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
          {STATS.map(s => (
            <div key={s.label}>
              <div className="text-4xl font-black text-violet-400 mb-1">{s.value}</div>
              <div className="text-sm text-white/40">{s.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-24 px-8">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <div className="text-xs font-semibold text-violet-400 uppercase tracking-widest mb-3">Platform Features</div>
            <h2 className="text-4xl font-bold text-white mb-4">Everything you need to secure your stack</h2>
            <p className="text-white/40 max-w-xl mx-auto">From automated scanning to AI remediation — one platform for your entire security workflow.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {FEATURES.map((f, i) => (
              <div
                key={f.title}
                className="group p-6 rounded-2xl border border-white/6 bg-white/2 hover:bg-white/4 hover:border-white/10 transition-all cursor-default"
                onMouseEnter={() => setHoveredFeature(i)}
                onMouseLeave={() => setHoveredFeature(null)}
              >
                <div
                  className="w-10 h-10 rounded-xl flex items-center justify-center mb-4 transition-all"
                  style={{ background: `${f.color}18`, boxShadow: hoveredFeature === i ? `0 0 20px ${f.color}30` : "none" }}
                >
                  <f.icon size={20} style={{ color: f.color }} />
                </div>
                <h3 className="font-semibold text-white mb-2">{f.title}</h3>
                <p className="text-sm text-white/40 leading-relaxed">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* OWASP */}
      <section id="owasp" className="py-20 px-8 bg-white/1 border-y border-white/5">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <div className="text-xs font-semibold text-cyan-400 uppercase tracking-widest mb-3">Compliance Coverage</div>
            <h2 className="text-3xl font-bold text-white mb-3">Full OWASP Top 10 Coverage</h2>
            <p className="text-white/40">Automated detection and classification across all 10 OWASP categories.</p>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {OWASP.map((cat, i) => (
              <div key={cat} className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-white/3 border border-white/6 hover:border-cyan-500/30 hover:bg-cyan-500/5 transition-all group">
                <CheckCircle2 size={14} className="text-cyan-400 shrink-0 group-hover:scale-110 transition-transform" />
                <span className="text-xs text-white/60 group-hover:text-white/80 transition-colors leading-tight">{cat}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-24 px-8 text-center relative overflow-hidden">
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="w-[400px] h-[400px] rounded-full bg-violet-600/8 blur-[100px]" />
        </div>
        <div className="relative max-w-2xl mx-auto">
          <div className="flex items-center justify-center gap-1 mb-6">
            {[...Array(5)].map((_, i) => <Star key={i} size={16} className="text-yellow-400 fill-yellow-400" />)}
          </div>
          <h2 className="text-4xl font-bold text-white mb-4">Start securing your applications today</h2>
          <p className="text-white/40 mb-10">Join security teams using Bug Finder Pro to detect, prioritize, and remediate vulnerabilities faster.</p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <button className="group flex items-center gap-2 px-8 py-4 bg-violet-600 hover:bg-violet-500 text-white rounded-xl font-semibold transition-all shadow-xl shadow-violet-500/25 text-lg">
              Get Started Free
              <ChevronRight size={18} className="group-hover:translate-x-0.5 transition-transform" />
            </button>
            <button className="px-8 py-4 border border-white/10 hover:border-white/20 text-white/60 hover:text-white rounded-xl font-medium transition-all hover:bg-white/5 text-lg">
              View Demo
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 px-8 border-t border-white/5 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-md bg-violet-600 flex items-center justify-center">
            <Shield size={14} className="text-white" />
          </div>
          <span className="font-semibold text-white/60">Bug Finder Pro</span>
        </div>
        <p className="text-xs text-white/25">© 2026 Bug Finder Pro. Security Operations Platform.</p>
        <div className="flex items-center gap-2 text-xs text-white/25">
          <Activity size={12} className="text-green-400" />
          All systems operational
        </div>
      </footer>
    </div>
  );
}
