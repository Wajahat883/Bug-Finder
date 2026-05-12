import { useState, useEffect, useRef } from "react";
import { useLocation } from "wouter";
import {
  Shield, Zap, Brain, GitBranch, BarChart3, Lock,
  ChevronRight, Terminal, CheckCircle2, Activity,
  ArrowRight, Star, Cpu, Globe, Eye, AlertTriangle,
} from "lucide-react";
import { useGetMe } from "@/api-client";

/* ── data ── */
const STATS = [
  { value: 112, suffix: "+", label: "Vulnerabilities" },
  { value: 39,  suffix: "",  label: "Scanner Modules" },
  { value: 18,  suffix: "",  label: "AI Endpoints"    },
  { value: 100, suffix: "%", label: "Risk Coverage"   },
];

const FEATURES = [
  { icon: Brain,    title: "AI-Powered Analysis",   desc: "Claude streams real-time executive summaries and remediation advice for every finding.",      color: "#a855f7" },
  { icon: Zap,      title: "Live Scan Streaming",    desc: "Watch vulnerabilities appear as they're discovered with SSE-powered real-time feeds.",         color: "#06b6d4" },
  { icon: Shield,   title: "CVSS 3.1 Scoring",       desc: "Interactive CVSS calculator with automatic severity classification across all levels.",         color: "#10b981" },
  { icon: GitBranch,"title": "GitHub Integration",   desc: "One-click issue creation for any finding directly into your repo with full context.",           color: "#f59e0b" },
  { icon: BarChart3, title: "Executive Dashboard",   desc: "Board-ready risk posture charts, OWASP heatmaps, and attack surface topology graphs.",          color: "#ef4444" },
  { icon: Lock,     title: "SLA Enforcement",         desc: "Automatic deadline tracking — Critical: 24h, High: 72h, Medium: 7d — with urgency alerts.",    color: "#ec4899" },
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

const HOW_STEPS = [
  { num: "01", icon: Globe,        title: "Add Target URL",       desc: "Enter any web application URL. Our engine fingerprints the stack automatically." },
  { num: "02", icon: Cpu,          title: "AI Scans Everything",  desc: "39 scanner modules run in parallel — SQLi, XSS, CORS, headers, ports and more." },
  { num: "03", icon: Eye,          title: "Review Findings",      desc: "Real-time findings feed with CVSS scores, evidence, and AI-generated fix advice." },
  { num: "04", icon: AlertTriangle, title: "Remediate Fast",      desc: "SLA timers, GitHub issue creation, and executive reports keep your team on track." },
];

const TERMINAL_LINES = [
  { delay: 0,    icon: "›", ic: "#a855f7", text: "Initializing scan engine v3.2.1…",    tc: "rgba(255,255,255,0.35)" },
  { delay: 700,  icon: "✓", ic: "#4ade80", text: "TLS/SSL Certificate Check",           suffix: "Pass",     sc: "#4ade80" },
  { delay: 1300, icon: "✓", ic: "#4ade80", text: "Security Headers Analysis",           suffix: "3 issues", sc: "#facc15" },
  { delay: 1900, icon: "✓", ic: "#4ade80", text: "DNS Subdomain Enumeration",           suffix: "12 found", sc: "#06b6d4" },
  { delay: 2500, icon: "⚠", ic: "#facc15", text: "CORS Policy Misconfiguration",        suffix: "HIGH",     sc: "#facc15", tc: "#fde047" },
  { delay: 3100, icon: "✗", ic: "#f87171", text: "SQL Injection  /api/users",           suffix: "CRITICAL", sc: "#f87171", tc: "#fca5a5" },
  { delay: 3700, icon: "✗", ic: "#f87171", text: "JWT Weak Signing Secret",             suffix: "CRITICAL", sc: "#f87171", tc: "#fca5a5" },
  { delay: 4300, icon: "›", ic: "#a855f7", text: "AI generating remediation report",    tc: "rgba(255,255,255,0.3)", stream: true },
];

/* ── animated counter ── */
function Counter({ value, suffix }: { value: number; suffix: string }) {
  const [n, setN] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const done = useRef(false);
  useEffect(() => {
    const el = ref.current; if (!el) return;
    const obs = new IntersectionObserver(([e]) => {
      if (e?.isIntersecting && !done.current) {
        done.current = true;
        const t0 = performance.now();
        const dur = 2000;
        const tick = (now: number) => {
          const p = Math.min((now - t0) / dur, 1);
          setN(Math.floor((1 - Math.pow(1 - p, 3)) * value));
          if (p < 1) requestAnimationFrame(tick); else setN(value);
        };
        requestAnimationFrame(tick);
      }
    }, { threshold: 0.5 });
    obs.observe(el);
    return () => obs.disconnect();
  }, [value]);
  return <div ref={ref} className="text-5xl font-black" style={{ color: "#c084fc", textShadow: "0 0 30px rgba(192,132,252,0.6)" }}>{n}{suffix}</div>;
}

/* ── typewriter terminal ── */
function TypewriterTerminal() {
  const [visible, setVisible] = useState<number[]>([]);
  useEffect(() => {
    const timers = TERMINAL_LINES.map((l, i) => setTimeout(() => setVisible(v => [...v, i]), l.delay));
    return () => timers.forEach(clearTimeout);
  }, []);
  return (
    <div className="rounded-2xl overflow-hidden" style={{ background: "rgba(13,5,32,0.95)", border: "1px solid rgba(168,85,247,0.25)", boxShadow: "0 0 40px rgba(109,40,217,0.2), inset 0 0 40px rgba(0,0,0,0.3)" }}>
      {/* title bar */}
      <div className="flex items-center gap-2 px-5 py-3" style={{ borderBottom: "1px solid rgba(168,85,247,0.15)", background: "rgba(168,85,247,0.05)" }}>
        <div className="w-3 h-3 rounded-full" style={{ background: "#ef4444", boxShadow: "0 0 6px #ef4444" }} />
        <div className="w-3 h-3 rounded-full" style={{ background: "#f59e0b", boxShadow: "0 0 6px #f59e0b" }} />
        <div className="w-3 h-3 rounded-full" style={{ background: "#22c55e", boxShadow: "0 0 6px #22c55e" }} />
        <span className="ml-3 text-xs font-mono" style={{ color: "rgba(168,85,247,0.6)" }}>bug-finder-pro — live scan</span>
        <div className="ml-auto flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full animate-pulse" style={{ background: "#22c55e", display: "inline-block" }} />
          <span className="text-xs font-mono" style={{ color: "#4ade80" }}>LIVE</span>
        </div>
      </div>
      {/* output */}
      <div className="p-5 font-mono text-xs space-y-2 min-h-[200px]">
        {visible.length === 0 && (
          <p style={{ color: "rgba(168,85,247,0.5)" }}>› <span className="animate-pulse">█</span></p>
        )}
        {TERMINAL_LINES.map((l, i) => !visible.includes(i) ? null : (
          <p key={i} className="flex items-start gap-2 leading-5">
            <span className="shrink-0" style={{ color: l.ic }}>{l.icon}</span>
            <span style={{ color: l.tc ?? "rgba(255,255,255,0.5)" }}>{l.text}</span>
            {l.suffix && (
              <span className="ml-auto shrink-0 px-1.5 py-0.5 rounded text-[10px] font-bold" style={{ background: `${l.sc}20`, color: l.sc, border: `1px solid ${l.sc}40` }}>{l.suffix}</span>
            )}
            {l.stream && <span className="animate-pulse" style={{ color: "#a855f7" }}>█</span>}
          </p>
        ))}
      </div>
    </div>
  );
}

/* ── dot grid bg ── */
function DotGrid({ opacity = 0.07 }: { opacity?: number }) {
  return (
    <div className="absolute inset-0 pointer-events-none" style={{ opacity }}>
      <svg width="100%" height="100%">
        <defs>
          <pattern id="dots" x="0" y="0" width="28" height="28" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="1" fill="rgba(168,85,247,1)" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#dots)" />
      </svg>
    </div>
  );
}

/* ── glow blob ── */
function GlowBlob({ x, y, size, color, opacity }: { x: string; y: string; size: number; color: string; opacity: number }) {
  return (
    <div className="absolute pointer-events-none rounded-full" style={{ left: x, top: y, width: size, height: size, background: color, opacity, filter: `blur(${size * 0.55}px)`, transform: "translate(-50%,-50%)" }} />
  );
}

/* ── main ── */
export default function Landing() {
  const [, nav] = useLocation();
  const [hoveredF, setHoveredF] = useState<number | null>(null);
  const [owaspPulse, setOwaspPulse] = useState<number | null>(null);
  const { data: user } = useGetMe();

  useEffect(() => { if (user) nav("/dashboard"); }, [user, nav]);

  useEffect(() => {
    const id = setInterval(() => {
      const i = Math.floor(Math.random() * OWASP.length);
      setOwaspPulse(i);
      setTimeout(() => setOwaspPulse(null), 900);
    }, 2000);
    return () => clearInterval(id);
  }, []);

  async function handleDemo() {
    try { const r = await fetch("/api/auth/demo", { method: "POST", credentials: "include" }); if (r.ok) nav("/dashboard"); } catch {}
  }

  return (
    <>
      <style>{`
        @keyframes floatY { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-14px)} }
        @keyframes pulseGlow { 0%,100%{box-shadow:0 0 30px rgba(109,40,217,0.4)} 50%{box-shadow:0 0 60px rgba(109,40,217,0.75),0 0 100px rgba(109,40,217,0.3)} }
        @keyframes shimmer { 0%{background-position:0% center} 100%{background-position:200% center} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(28px)} to{opacity:1;transform:translateY(0)} }
        @keyframes borderRotate { 0%{background-position:0% 50%} 100%{background-position:200% 50%} }
        @keyframes ticker { 0%{transform:translateX(0)} 100%{transform:translateX(-50%)} }
        .fade-up { animation: fadeUp 0.7s ease both; }
        .fade-up-1 { animation: fadeUp 0.7s 0.1s ease both; }
        .fade-up-2 { animation: fadeUp 0.7s 0.2s ease both; }
        .fade-up-3 { animation: fadeUp 0.7s 0.3s ease both; }
        .fade-up-4 { animation: fadeUp 0.7s 0.4s ease both; }
        .glow-btn { transition: all 0.25s ease; }
        .glow-btn:hover { transform: translateY(-2px); box-shadow: 0 0 50px rgba(109,40,217,0.7), 0 8px 30px rgba(109,40,217,0.5) !important; }
        .ghost-btn { transition: all 0.25s ease; }
        .ghost-btn:hover { background: rgba(168,85,247,0.1) !important; border-color: rgba(168,85,247,0.5) !important; color: #e9d5ff !important; }
        .feature-card { transition: all 0.3s ease; }
        .feature-card:hover { transform: translateY(-4px); }
        .stat-box { transition: all 0.3s ease; }
        .stat-box:hover { border-color: rgba(168,85,247,0.5) !important; box-shadow: 0 0 30px rgba(109,40,217,0.25) !important; transform: translateY(-3px); }
        .robot-glow { animation: floatY 4s ease-in-out infinite; filter: drop-shadow(0 0 40px rgba(168,85,247,0.7)) drop-shadow(0 0 80px rgba(109,40,217,0.4)); }
        .step-num { background: linear-gradient(135deg,#7c3aed,#a855f7); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
      `}</style>

      <div className="min-h-screen font-sans text-white overflow-x-hidden" style={{ background: "#0c0518" }}>

        {/* ── NAV ── */}
        <nav className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-8 py-4"
          style={{ background: "rgba(12,5,24,0.85)", backdropFilter: "blur(20px)", borderBottom: "1px solid rgba(168,85,247,0.15)", boxShadow: "0 1px 0 0 rgba(168,85,247,0.08)" }}>
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl flex items-center justify-center" style={{ background: "linear-gradient(135deg,#7c3aed,#a855f7)", boxShadow: "0 0 20px rgba(124,58,237,0.6)" }}>
              <Shield size={18} className="text-white" />
            </div>
            <span className="font-bold text-lg tracking-tight">Bug Finder <span style={{ color: "#c084fc" }}>Pro</span></span>
          </div>
          <div className="hidden md:flex items-center gap-8 text-sm" style={{ color: "rgba(255,255,255,0.5)" }}>
            {["Features","How It Works","OWASP","Coverage"].map(l => (
              <a key={l} href={`#${l.toLowerCase().replace(/ /g,"-")}`} className="hover:text-white transition-colors hover:text-purple-300">{l}</a>
            ))}
          </div>
          <div className="flex items-center gap-3">
            <button onClick={() => nav("/login")} className="ghost-btn px-4 py-2 text-sm rounded-lg transition-all" style={{ color: "rgba(255,255,255,0.55)", border: "1px solid rgba(255,255,255,0.08)" }}>Sign In</button>
            <button onClick={() => nav("/login")} className="glow-btn px-4 py-2 text-sm font-semibold rounded-lg text-white" style={{ background: "linear-gradient(135deg,#7c3aed,#9333ea)", boxShadow: "0 0 25px rgba(109,40,217,0.5)" }}>
              Start Free Scan
            </button>
          </div>
        </nav>

        {/* ── HERO ── */}
        <section className="relative pt-28 pb-16 px-8 overflow-hidden" style={{ minHeight: "100vh" }}>
          {/* bg glows */}
          <GlowBlob x="15%"  y="30%"  size={500} color="#6d28d9" opacity={0.18} />
          <GlowBlob x="80%"  y="20%"  size={400} color="#7c3aed" opacity={0.14} />
          <GlowBlob x="60%"  y="70%"  size={300} color="#4c1d95" opacity={0.12} />
          <DotGrid opacity={0.06} />

          <div className="relative z-10 max-w-7xl mx-auto flex flex-col lg:flex-row items-center gap-12 lg:gap-0">
            {/* left */}
            <div className="flex-1 text-center lg:text-left">
              <div className="fade-up inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium mb-6"
                style={{ border: "1px solid rgba(168,85,247,0.4)", background: "rgba(168,85,247,0.1)", color: "#d8b4fe" }}>
                <span className="w-1.5 h-1.5 rounded-full animate-pulse inline-block" style={{ background: "#c084fc" }} />
                AI-Powered Security Operations Platform
              </div>

              <h1 className="fade-up-1 text-5xl md:text-6xl xl:text-7xl font-black leading-tight tracking-tight mb-6">
                Find <span style={{ background: "linear-gradient(90deg,#c084fc,#67e8f9,#c084fc)", backgroundSize: "200% auto", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", animation: "shimmer 4s linear infinite" }}>Bugs.</span>
                <br />
                Before They{" "}
                <span style={{ color: "#c084fc", textShadow: "0 0 40px rgba(192,132,252,0.5)" }}>Find You.</span>
              </h1>

              <p className="fade-up-2 text-base md:text-lg leading-relaxed mb-10 max-w-xl mx-auto lg:mx-0" style={{ color: "rgba(255,255,255,0.45)" }}>
                Enterprise-grade vulnerability scanning with real-time AI analysis, OWASP Top 10 coverage,
                SLA enforcement, and one-click GitHub issue creation.
              </p>

              <div className="fade-up-3 flex flex-col sm:flex-row items-center justify-center lg:justify-start gap-4 mb-12">
                <button onClick={() => nav("/login")} className="glow-btn group flex items-center gap-2 px-7 py-3.5 text-white rounded-xl font-semibold text-base"
                  style={{ background: "linear-gradient(135deg,#7c3aed,#9333ea)", boxShadow: "0 0 30px rgba(109,40,217,0.55)" }}>
                  Launch Your First Scan
                  <ArrowRight size={16} className="group-hover:translate-x-1 transition-transform" />
                </button>
                <button onClick={handleDemo} className="ghost-btn flex items-center gap-2 px-7 py-3.5 rounded-xl font-medium text-base"
                  style={{ border: "1px solid rgba(168,85,247,0.3)", color: "rgba(255,255,255,0.6)" }}>
                  <Terminal size={16} />
                  Live Demo
                </button>
              </div>

              {/* mini trust badges */}
              <div className="fade-up-4 flex items-center gap-5 justify-center lg:justify-start">
                {["OWASP Top 10","CVE Enriched","CVSS 3.1","SARIF Export"].map(b => (
                  <span key={b} className="flex items-center gap-1.5 text-xs" style={{ color: "rgba(255,255,255,0.4)" }}>
                    <CheckCircle2 size={12} style={{ color: "#a855f7" }} />{b}
                  </span>
                ))}
              </div>
            </div>

            {/* right — robot */}
            <div className="flex-1 flex items-center justify-center relative">
              {/* outer ring glow */}
              <div className="absolute w-80 h-80 md:w-96 md:h-96 rounded-full pointer-events-none"
                style={{ background: "radial-gradient(circle, rgba(109,40,217,0.25) 0%, transparent 70%)", animation: "pulseGlow 3s ease-in-out infinite" }} />
              {/* hexagon frame */}
              <div className="relative" style={{ width: 340, height: 340 }}>
                <svg className="absolute inset-0 w-full h-full" viewBox="0 0 340 340" fill="none">
                  <polygon points="170,8 325,92 325,248 170,332 15,248 15,92"
                    stroke="url(#hexGrad)" strokeWidth="1.5" fill="rgba(109,40,217,0.06)" />
                  <polygon points="170,28 305,102 305,238 170,312 35,238 35,102"
                    stroke="rgba(168,85,247,0.15)" strokeWidth="1" fill="none" strokeDasharray="4 6" />
                  <defs>
                    <linearGradient id="hexGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                      <stop offset="0%" stopColor="#7c3aed" stopOpacity="0.8" />
                      <stop offset="50%" stopColor="#c084fc" stopOpacity="0.6" />
                      <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.5" />
                    </linearGradient>
                  </defs>
                </svg>
                {/* corner circuit dots */}
                {[
                  { top: "8%",  left: "50%",  transform: "translateX(-50%)" },
                  { top: "50%", left: "96%",  transform: "translateY(-50%)" },
                  { top: "92%", left: "50%",  transform: "translateX(-50%)" },
                  { top: "50%", left: "4%",   transform: "translateY(-50%)" },
                ].map((s, i) => (
                  <div key={i} className="absolute w-2 h-2 rounded-full" style={{ ...s, background: "#a855f7", boxShadow: "0 0 8px #a855f7" }} />
                ))}
                <img src="/robot.jpg" alt="Cyber AI" className="robot-glow absolute"
                  style={{ width: "82%", height: "82%", objectFit: "contain", top: "50%", left: "50%", transform: "translate(-50%,-50%)", borderRadius: "50%" }} />
              </div>

              {/* floating badges */}
              <div className="absolute top-4 right-0 px-3 py-2 rounded-xl text-xs font-mono"
                style={{ background: "rgba(13,5,32,0.9)", border: "1px solid rgba(239,68,68,0.4)", color: "#f87171", boxShadow: "0 0 20px rgba(239,68,68,0.15)", animation: "floatY 3s 0.5s ease-in-out infinite" }}>
                ✗ SQL Injection — CRITICAL
              </div>
              <div className="absolute bottom-8 left-0 px-3 py-2 rounded-xl text-xs font-mono"
                style={{ background: "rgba(13,5,32,0.9)", border: "1px solid rgba(74,222,128,0.4)", color: "#4ade80", boxShadow: "0 0 20px rgba(74,222,128,0.15)", animation: "floatY 3.5s 1s ease-in-out infinite" }}>
                ✓ 39 Scanners Active
              </div>
              <div className="absolute bottom-24 right-2 px-3 py-2 rounded-xl text-xs font-mono"
                style={{ background: "rgba(13,5,32,0.9)", border: "1px solid rgba(250,204,21,0.4)", color: "#facc15", boxShadow: "0 0 20px rgba(250,204,21,0.1)", animation: "floatY 4s 1.5s ease-in-out infinite" }}>
                ⚠ CORS — HIGH
              </div>
            </div>
          </div>
        </section>

        {/* ── STATS ── */}
        <section id="coverage" className="py-14 px-8 relative overflow-hidden" style={{ background: "rgba(0,0,0,0.3)", borderTop: "1px solid rgba(168,85,247,0.12)", borderBottom: "1px solid rgba(168,85,247,0.12)" }}>
          <GlowBlob x="50%" y="50%" size={600} color="#4c1d95" opacity={0.1} />
          <DotGrid opacity={0.04} />
          <div className="relative z-10 max-w-5xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-6">
            {STATS.map(s => (
              <div key={s.label} className="stat-box text-center px-6 py-8 rounded-2xl cursor-default"
                style={{ background: "rgba(109,40,217,0.08)", border: "1px solid rgba(168,85,247,0.2)", boxShadow: "0 0 20px rgba(109,40,217,0.1)" }}>
                <Counter value={s.value} suffix={s.suffix} />
                <div className="text-sm mt-2 font-medium" style={{ color: "rgba(255,255,255,0.4)" }}>{s.label}</div>
              </div>
            ))}
          </div>
        </section>

        {/* ── TERMINAL PREVIEW (full-width banner) ── */}
        <section className="py-20 px-8 relative overflow-hidden" style={{ background: "linear-gradient(180deg,#0c0518 0%,#110830 50%,#0c0518 100%)" }}>
          <GlowBlob x="50%" y="50%" size={700} color="#6d28d9" opacity={0.12} />
          <DotGrid opacity={0.05} />
          <div className="relative z-10 max-w-6xl mx-auto flex flex-col lg:flex-row items-center gap-12">
            <div className="flex-1">
              <div className="text-xs font-semibold uppercase tracking-widest mb-3 font-mono" style={{ color: "#a855f7" }}>// Live Scan Engine</div>
              <h2 className="text-4xl font-bold mb-5">Watch the scanner <span style={{ color: "#c084fc" }}>work in real-time</span></h2>
              <p className="leading-relaxed mb-8" style={{ color: "rgba(255,255,255,0.4)" }}>
                Every vulnerability surfaces instantly as our 39 scanner modules sweep your target.
                No waiting — results stream live via SSE direct to your dashboard.
              </p>
              <ul className="space-y-3">
                {["39 scanner modules in parallel","AI remediation for every finding","CVSS score auto-calculated","GitHub issue in one click"].map(t => (
                  <li key={t} className="flex items-center gap-3 text-sm" style={{ color: "rgba(255,255,255,0.55)" }}>
                    <span className="w-5 h-5 rounded-full flex items-center justify-center shrink-0" style={{ background: "rgba(168,85,247,0.2)", border: "1px solid rgba(168,85,247,0.4)" }}>
                      <CheckCircle2 size={11} style={{ color: "#a855f7" }} />
                    </span>
                    {t}
                  </li>
                ))}
              </ul>
            </div>
            <div className="flex-1 w-full">
              <TypewriterTerminal />
            </div>
          </div>
        </section>

        {/* ── HOW IT WORKS ── */}
        <section id="how-it-works" className="py-24 px-8 relative overflow-hidden">
          <GlowBlob x="80%" y="50%" size={400} color="#7c3aed" opacity={0.1} />
          <DotGrid opacity={0.05} />
          <div className="relative z-10 max-w-6xl mx-auto">
            <div className="text-center mb-16">
              <div className="text-xs font-semibold uppercase tracking-widest mb-3 font-mono" style={{ color: "#a855f7" }}>// How It Works</div>
              <h2 className="text-4xl font-bold mb-4">From URL to <span style={{ color: "#c084fc" }}>full report</span> in minutes</h2>
              <p style={{ color: "rgba(255,255,255,0.35)" }}>Four steps — all automated, all AI-powered.</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 relative">
              {/* connecting line */}
              <div className="hidden lg:block absolute top-12 left-[12.5%] right-[12.5%] h-px" style={{ background: "linear-gradient(90deg, transparent, rgba(168,85,247,0.4), rgba(168,85,247,0.4), transparent)" }} />
              {HOW_STEPS.map((step, i) => (
                <div key={step.num} className="relative flex flex-col items-center text-center p-6 rounded-2xl"
                  style={{ background: "rgba(109,40,217,0.07)", border: "1px solid rgba(168,85,247,0.18)", boxShadow: "0 0 20px rgba(109,40,217,0.08)", animationDelay: `${i * 0.1}s` }}>
                  <div className="w-14 h-14 rounded-2xl flex items-center justify-center mb-4 relative z-10"
                    style={{ background: "linear-gradient(135deg,rgba(124,58,237,0.3),rgba(168,85,247,0.2))", border: "1px solid rgba(168,85,247,0.35)", boxShadow: "0 0 20px rgba(109,40,217,0.25)" }}>
                    <step.icon size={22} style={{ color: "#c084fc" }} />
                  </div>
                  <div className="text-2xl font-black mb-2 step-num">{step.num}</div>
                  <h3 className="font-semibold text-white mb-2">{step.title}</h3>
                  <p className="text-sm leading-relaxed" style={{ color: "rgba(255,255,255,0.38)" }}>{step.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── FEATURES BENTO ── */}
        <section id="features" className="py-24 px-8 relative overflow-hidden" style={{ background: "rgba(0,0,0,0.2)" }}>
          <GlowBlob x="20%" y="50%" size={500} color="#6d28d9" opacity={0.1} />
          <DotGrid opacity={0.05} />
          <div className="relative z-10 max-w-6xl mx-auto">
            <div className="text-center mb-16">
              <div className="text-xs font-semibold uppercase tracking-widest mb-3 font-mono" style={{ color: "#a855f7" }}>// Platform Features</div>
              <h2 className="text-4xl font-bold mb-4">Everything you need to <span style={{ color: "#c084fc" }}>secure your stack</span></h2>
              <p style={{ color: "rgba(255,255,255,0.35)" }}>One platform for your entire security workflow.</p>
            </div>
            {/* bento grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
              {FEATURES.map((f, i) => (
                <div key={f.title}
                  className="feature-card p-6 rounded-2xl cursor-default relative overflow-hidden group"
                  style={{
                    background: hoveredF === i ? `linear-gradient(135deg, ${f.color}12, rgba(13,5,32,0.9))` : "rgba(255,255,255,0.02)",
                    border: hoveredF === i ? `1px solid ${f.color}45` : "1px solid rgba(168,85,247,0.12)",
                    boxShadow: hoveredF === i ? `0 0 40px ${f.color}15, inset 0 0 20px ${f.color}08` : "none",
                  }}
                  onMouseEnter={() => setHoveredF(i)}
                  onMouseLeave={() => setHoveredF(null)}
                >
                  {/* top glow line */}
                  <div className="absolute top-0 left-0 right-0 h-px transition-opacity duration-300"
                    style={{ background: `linear-gradient(90deg,transparent,${f.color},transparent)`, opacity: hoveredF === i ? 1 : 0 }} />

                  <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-5 transition-all duration-300"
                    style={{ background: `${f.color}18`, border: `1px solid ${f.color}30`, boxShadow: hoveredF === i ? `0 0 25px ${f.color}35` : "none" }}>
                    <f.icon size={22} style={{ color: f.color }} />
                  </div>
                  <h3 className="font-semibold text-white mb-2 text-base">{f.title}</h3>
                  <p className="text-sm leading-relaxed" style={{ color: "rgba(255,255,255,0.37)" }}>{f.desc}</p>

                  {hoveredF === i && (
                    <div className="absolute bottom-4 right-4 text-[10px] font-mono px-2 py-0.5 rounded"
                      style={{ background: `${f.color}20`, color: f.color, border: `1px solid ${f.color}35` }}>
                      ACTIVE
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── OWASP ── */}
        <section id="owasp" className="py-20 px-8 relative overflow-hidden">
          <GlowBlob x="50%" y="50%" size={500} color="#4c1d95" opacity={0.12} />
          <DotGrid opacity={0.05} />
          <div className="relative z-10 max-w-5xl mx-auto">
            <div className="text-center mb-12">
              <div className="text-xs font-semibold uppercase tracking-widest mb-3 font-mono" style={{ color: "#67e8f9" }}>// Compliance Coverage</div>
              <h2 className="text-3xl font-bold text-white mb-3">Full <span style={{ color: "#c084fc" }}>OWASP Top 10</span> Coverage</h2>
              <p style={{ color: "rgba(255,255,255,0.35)" }}>Automated detection and classification across all 10 OWASP categories.</p>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              {OWASP.map((cat, i) => (
                <div key={cat} className="flex items-center gap-2 px-3 py-3 rounded-xl transition-all duration-200 cursor-default"
                  style={{
                    background: owaspPulse === i ? "rgba(239,68,68,0.1)" : "rgba(109,40,217,0.07)",
                    border: owaspPulse === i ? "1px solid rgba(239,68,68,0.45)" : "1px solid rgba(168,85,247,0.15)",
                    boxShadow: owaspPulse === i ? "0 0 20px rgba(239,68,68,0.15)" : "none",
                  }}>
                  <CheckCircle2 size={13} style={{ color: owaspPulse === i ? "#f87171" : "#a855f7", flexShrink: 0, transition: "color 0.2s" }} />
                  <span className="text-xs leading-tight" style={{ color: owaspPulse === i ? "#fca5a5" : "rgba(255,255,255,0.5)", transition: "color 0.2s" }}>{cat}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── CTA BANNER ── */}
        <section className="py-24 px-8 relative overflow-hidden" style={{ background: "linear-gradient(135deg,#0c0518 0%,#180830 50%,#0c0518 100%)" }}>
          <GlowBlob x="30%" y="50%" size={500} color="#7c3aed" opacity={0.15} />
          <GlowBlob x="70%" y="50%" size={400} color="#4c1d95" opacity={0.12} />
          <DotGrid opacity={0.06} />

          {/* border glow frame */}
          <div className="relative z-10 max-w-4xl mx-auto rounded-3xl p-12 text-center"
            style={{ background: "rgba(109,40,217,0.08)", border: "1px solid rgba(168,85,247,0.25)", boxShadow: "0 0 60px rgba(109,40,217,0.15), inset 0 0 60px rgba(0,0,0,0.2)" }}>
            {/* top accent line */}
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-32 h-px" style={{ background: "linear-gradient(90deg,transparent,#a855f7,transparent)" }} />

            <div className="flex items-center justify-center gap-1 mb-6">
              {[...Array(5)].map((_, i) => <Star key={i} size={16} style={{ color: "#facc15", fill: "#facc15" }} />)}
            </div>
            <h2 className="text-4xl md:text-5xl font-black mb-4">
              Start <span style={{ color: "#c084fc" }}>securing</span> your<br />applications today
            </h2>
            <p className="mb-10 text-lg max-w-xl mx-auto" style={{ color: "rgba(255,255,255,0.38)" }}>
              Join security teams using Bug Finder Pro to detect, prioritize, and remediate vulnerabilities faster than ever.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <button onClick={() => nav("/login")} className="glow-btn group flex items-center gap-2 px-9 py-4 text-white rounded-xl font-semibold text-lg"
                style={{ background: "linear-gradient(135deg,#7c3aed,#9333ea)", boxShadow: "0 0 35px rgba(109,40,217,0.6)" }}>
                Get Started Free
                <ChevronRight size={18} className="group-hover:translate-x-1 transition-transform" />
              </button>
              <button onClick={handleDemo} className="ghost-btn px-9 py-4 rounded-xl font-medium text-lg"
                style={{ border: "1px solid rgba(168,85,247,0.3)", color: "rgba(255,255,255,0.55)" }}>
                View Live Demo
              </button>
            </div>
          </div>
        </section>

        {/* ── FOOTER ── */}
        <footer className="py-8 px-8 flex flex-col md:flex-row items-center justify-between gap-4"
          style={{ borderTop: "1px solid rgba(168,85,247,0.12)", background: "rgba(0,0,0,0.2)" }}>
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: "linear-gradient(135deg,#7c3aed,#a855f7)" }}>
              <Shield size={14} className="text-white" />
            </div>
            <span className="font-bold font-mono" style={{ color: "rgba(255,255,255,0.45)" }}>Bug Finder Pro</span>
          </div>
          <p className="text-xs font-mono" style={{ color: "rgba(255,255,255,0.2)" }}>© 2026 Bug Finder Pro — Security Operations Platform</p>
          <div className="flex items-center gap-2 text-xs font-mono">
            <Activity size={12} style={{ color: "#4ade80" }} />
            <span style={{ color: "#4ade80" }}>All systems operational</span>
          </div>
        </footer>
      </div>
    </>
  );
}
