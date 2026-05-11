import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import {
  Shield, Zap, Brain, GitBranch, BarChart3, Lock,
  ChevronRight, Terminal, CheckCircle2, Activity,
  ArrowRight, Star,
} from "lucide-react";
import { useGetMe } from "@/api-client";

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

export default function Landing() {
  const [, nav] = useLocation();
  const [hoveredFeature, setHoveredFeature] = useState<number | null>(null);
  const { data: user } = useGetMe();

  useEffect(() => {
    if (user) nav("/dashboard");
  }, [user, nav]);

  async function handleDemo() {
    try {
      const r = await fetch("/api/auth/demo", { method: "POST", credentials: "include" });
      if (r.ok) nav("/dashboard");
    } catch {}
  }

  return (
    <div className="min-h-screen text-white font-sans overflow-x-hidden" style={{ background: "#0a0a0f" }}>
      {/* Nav */}
      <nav className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-8 py-4 backdrop-blur-xl" style={{ borderBottom: "1px solid rgba(255,255,255,0.05)", background: "rgba(10,10,15,0.85)" }}>
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: "#7c3aed", boxShadow: "0 0 20px rgba(124,58,237,0.4)" }}>
            <Shield size={18} className="text-white" />
          </div>
          <span className="font-bold text-lg tracking-tight">Bug Finder <span style={{ color: "#a78bfa" }}>Pro</span></span>
        </div>
        <div className="hidden md:flex items-center gap-6 text-sm" style={{ color: "rgba(255,255,255,0.5)" }}>
          <a href="#features" className="hover:text-white transition-colors">Features</a>
          <a href="#owasp" className="hover:text-white transition-colors">OWASP</a>
          <a href="#coverage" className="hover:text-white transition-colors">Coverage</a>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => nav("/login")}
            className="px-4 py-2 text-sm transition-colors hover:text-white"
            style={{ color: "rgba(255,255,255,0.6)" }}
          >
            Sign In
          </button>
          <button
            onClick={() => nav("/login")}
            className="px-4 py-2 text-sm font-medium rounded-lg text-white transition-all"
            style={{ background: "#7c3aed", boxShadow: "0 4px 15px rgba(124,58,237,0.3)" }}
          >
            Start Free Scan
          </button>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative pt-32 pb-24 px-8 text-center overflow-hidden">
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="w-[700px] h-[700px] rounded-full" style={{ background: "rgba(124,58,237,0.08)", filter: "blur(120px)" }} />
        </div>
        <div className="absolute top-20 left-1/4 w-72 h-72 rounded-full pointer-events-none" style={{ background: "rgba(6,182,212,0.04)", filter: "blur(100px)" }} />

        <div className="relative z-10">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium mb-6" style={{ border: "1px solid rgba(139,92,246,0.35)", background: "rgba(139,92,246,0.1)", color: "#c4b5fd" }}>
            <div className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "#a78bfa" }} />
            AI-Powered Security Operations Platform
          </div>

          <h1 className="text-5xl md:text-7xl font-black tracking-tight mb-6 leading-none">
            Find Bugs.{" "}
            <span style={{ background: "linear-gradient(90deg, #a78bfa, #67e8f9, #a78bfa)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
              Before They Find You.
            </span>
          </h1>
          <p className="text-lg max-w-2xl mx-auto mb-10 leading-relaxed" style={{ color: "rgba(255,255,255,0.45)" }}>
            Enterprise-grade vulnerability scanning with real-time AI analysis, OWASP Top 10 coverage,
            SLA enforcement, and one-click GitHub issue creation — all in one platform.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <button
              onClick={() => nav("/login")}
              className="group flex items-center gap-2 px-6 py-3.5 text-white rounded-xl font-semibold transition-all"
              style={{ background: "#7c3aed", boxShadow: "0 8px 30px rgba(124,58,237,0.35)" }}
            >
              Launch Your First Scan
              <ArrowRight size={16} className="group-hover:translate-x-0.5 transition-transform" />
            </button>
            <button
              onClick={handleDemo}
              className="flex items-center gap-2 px-6 py-3.5 rounded-xl font-medium transition-all hover:text-white"
              style={{ border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.6)" }}
            >
              <Terminal size={16} />
              Continue as Demo
            </button>
          </div>
        </div>

        {/* Terminal preview */}
        <div className="mt-16 max-w-3xl mx-auto rounded-2xl overflow-hidden shadow-2xl text-left relative z-10"
          style={{ border: "1px solid rgba(255,255,255,0.07)", background: "#0f0f1a", boxShadow: "0 40px 80px rgba(0,0,0,0.6)" }}>
          <div className="flex items-center gap-2 px-4 py-3" style={{ borderBottom: "1px solid rgba(255,255,255,0.05)", background: "rgba(255,255,255,0.01)" }}>
            <div className="w-3 h-3 rounded-full" style={{ background: "rgba(239,68,68,0.7)" }} />
            <div className="w-3 h-3 rounded-full" style={{ background: "rgba(234,179,8,0.7)" }} />
            <div className="w-3 h-3 rounded-full" style={{ background: "rgba(34,197,94,0.7)" }} />
            <span className="ml-2 text-xs font-mono" style={{ color: "rgba(255,255,255,0.25)" }}>bug-finder-pro — scan engine</span>
          </div>
          <div className="p-5 font-mono text-xs space-y-1.5">
            <p><span style={{ color: "#4ade80" }}>✓</span> <span style={{ color: "rgba(255,255,255,0.45)" }}>TLS/SSL Certificate Check</span> <span style={{ color: "rgba(255,255,255,0.2)" }}>— Pass</span></p>
            <p><span style={{ color: "#4ade80" }}>✓</span> <span style={{ color: "rgba(255,255,255,0.45)" }}>Security Headers Analysis</span> <span style={{ color: "rgba(255,255,255,0.2)" }}>— 3 issues found</span></p>
            <p><span style={{ color: "#facc15" }}>⚠</span> <span style={{ color: "#fde047" }}>CORS Policy Misconfiguration</span> <span style={{ color: "rgba(250,204,21,0.5)" }}>— HIGH</span></p>
            <p><span style={{ color: "#f87171" }}>✗</span> <span style={{ color: "#fca5a5" }}>SQL Injection in /api/users</span> <span style={{ color: "rgba(248,113,113,0.5)" }}>— CRITICAL</span></p>
            <p><span style={{ color: "#f87171" }}>✗</span> <span style={{ color: "#fca5a5" }}>JWT Weak Signing Secret</span> <span style={{ color: "rgba(248,113,113,0.5)" }}>— CRITICAL</span></p>
            <p><span style={{ color: "#67e8f9" }}>›</span> <span style={{ color: "rgba(255,255,255,0.25)" }}>AI Summary generating</span><span className="animate-pulse" style={{ color: "#67e8f9" }}>...</span></p>
          </div>
        </div>
      </section>

      {/* Stats */}
      <section id="coverage" className="py-16 px-8" style={{ borderTop: "1px solid rgba(255,255,255,0.05)", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
        <div className="max-w-4xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
          {[
            { value: "112+", label: "Vulnerabilities Detected" },
            { value: "18", label: "Scans Completed" },
            { value: "5", label: "Targets Monitored" },
            { value: "100", label: "Risk Score Tracked" },
          ].map(s => (
            <div key={s.label}>
              <div className="text-4xl font-black mb-1" style={{ color: "#a78bfa" }}>{s.value}</div>
              <div className="text-sm" style={{ color: "rgba(255,255,255,0.35)" }}>{s.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-24 px-8">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <div className="text-xs font-semibold uppercase tracking-widest mb-3" style={{ color: "#a78bfa" }}>Platform Features</div>
            <h2 className="text-4xl font-bold text-white mb-4">Everything you need to secure your stack</h2>
            <p className="max-w-xl mx-auto" style={{ color: "rgba(255,255,255,0.35)" }}>From automated scanning to AI remediation — one platform for your entire security workflow.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {FEATURES.map((f, i) => (
              <div
                key={f.title}
                className="p-6 rounded-2xl transition-all cursor-default"
                style={{
                  border: hoveredFeature === i ? `1px solid rgba(255,255,255,0.1)` : "1px solid rgba(255,255,255,0.05)",
                  background: hoveredFeature === i ? "rgba(255,255,255,0.03)" : "rgba(255,255,255,0.01)",
                }}
                onMouseEnter={() => setHoveredFeature(i)}
                onMouseLeave={() => setHoveredFeature(null)}
              >
                <div
                  className="w-10 h-10 rounded-xl flex items-center justify-center mb-4 transition-all"
                  style={{
                    background: `${f.color}18`,
                    boxShadow: hoveredFeature === i ? `0 0 20px ${f.color}25` : "none",
                  }}
                >
                  <f.icon size={20} style={{ color: f.color }} />
                </div>
                <h3 className="font-semibold text-white mb-2">{f.title}</h3>
                <p className="text-sm leading-relaxed" style={{ color: "rgba(255,255,255,0.38)" }}>{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* OWASP */}
      <section id="owasp" className="py-20 px-8" style={{ background: "rgba(255,255,255,0.007)", borderTop: "1px solid rgba(255,255,255,0.05)", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <div className="text-xs font-semibold uppercase tracking-widest mb-3" style={{ color: "#67e8f9" }}>Compliance Coverage</div>
            <h2 className="text-3xl font-bold text-white mb-3">Full OWASP Top 10 Coverage</h2>
            <p style={{ color: "rgba(255,255,255,0.35)" }}>Automated detection and classification across all 10 OWASP categories.</p>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {OWASP.map(cat => (
              <div
                key={cat}
                className="flex items-center gap-2 px-3 py-2.5 rounded-xl transition-all group"
                style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)" }}
              >
                <CheckCircle2 size={14} style={{ color: "#67e8f9", flexShrink: 0 }} />
                <span className="text-xs leading-tight" style={{ color: "rgba(255,255,255,0.55)" }}>{cat}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-24 px-8 text-center relative overflow-hidden">
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="w-[500px] h-[500px] rounded-full" style={{ background: "rgba(124,58,237,0.06)", filter: "blur(100px)" }} />
        </div>
        <div className="relative max-w-2xl mx-auto">
          <div className="flex items-center justify-center gap-1 mb-6">
            {[...Array(5)].map((_, i) => <Star key={i} size={16} style={{ color: "#facc15", fill: "#facc15" }} />)}
          </div>
          <h2 className="text-4xl font-bold text-white mb-4">Start securing your applications today</h2>
          <p className="mb-10" style={{ color: "rgba(255,255,255,0.38)" }}>Join security teams using Bug Finder Pro to detect, prioritize, and remediate vulnerabilities faster.</p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <button
              onClick={() => nav("/login")}
              className="group flex items-center gap-2 px-8 py-4 text-white rounded-xl font-semibold text-lg transition-all"
              style={{ background: "#7c3aed", boxShadow: "0 8px 30px rgba(124,58,237,0.3)" }}
            >
              Get Started Free
              <ChevronRight size={18} className="group-hover:translate-x-0.5 transition-transform" />
            </button>
            <button
              onClick={handleDemo}
              className="px-8 py-4 rounded-xl font-medium text-lg transition-all hover:text-white"
              style={{ border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.5)" }}
            >
              View Demo
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 px-8 flex flex-col md:flex-row items-center justify-between gap-4" style={{ borderTop: "1px solid rgba(255,255,255,0.05)" }}>
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-md flex items-center justify-center" style={{ background: "#7c3aed" }}>
            <Shield size={14} className="text-white" />
          </div>
          <span className="font-semibold" style={{ color: "rgba(255,255,255,0.5)" }}>Bug Finder Pro</span>
        </div>
        <p className="text-xs" style={{ color: "rgba(255,255,255,0.2)" }}>© 2026 Bug Finder Pro. Security Operations Platform.</p>
        <div className="flex items-center gap-2 text-xs" style={{ color: "rgba(255,255,255,0.2)" }}>
          <Activity size={12} style={{ color: "#4ade80" }} />
          All systems operational
        </div>
      </footer>
    </div>
  );
}
