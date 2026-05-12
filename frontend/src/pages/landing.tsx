import { useState, useEffect, useRef, useCallback } from "react";
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

const TERMINAL_LINES = [
  { delay: 0,    icon: "›", iconColor: "#a78bfa", text: "Initializing scan engine v3.2.1...", textColor: "rgba(255,255,255,0.4)" },
  { delay: 600,  icon: "✓", iconColor: "#4ade80", text: "TLS/SSL Certificate Check", suffix: "— Pass", suffixColor: "rgba(255,255,255,0.2)" },
  { delay: 1100, icon: "✓", iconColor: "#4ade80", text: "Security Headers Analysis", suffix: "— 3 issues found", suffixColor: "rgba(255,255,255,0.2)" },
  { delay: 1700, icon: "✓", iconColor: "#4ade80", text: "DNS Subdomain Enumeration", suffix: "— 12 subdomains", suffixColor: "rgba(255,255,255,0.2)" },
  { delay: 2300, icon: "⚠", iconColor: "#facc15", text: "CORS Policy Misconfiguration", suffix: "— HIGH", suffixColor: "rgba(250,204,21,0.6)", textColor: "#fde047" },
  { delay: 2900, icon: "✗", iconColor: "#f87171", text: "SQL Injection in /api/users", suffix: "— CRITICAL", suffixColor: "rgba(248,113,113,0.6)", textColor: "#fca5a5" },
  { delay: 3500, icon: "✗", iconColor: "#f87171", text: "JWT Weak Signing Secret", suffix: "— CRITICAL", suffixColor: "rgba(248,113,113,0.6)", textColor: "#fca5a5" },
  { delay: 4100, icon: "›", iconColor: "#67e8f9", text: "AI Summary generating", textColor: "rgba(255,255,255,0.25)", streaming: true },
];

const CVE_TICKER = [
  { id: "CVE-2024-3400", sev: "CRITICAL", desc: "PAN-OS Command Injection" },
  { id: "CVE-2024-21762", sev: "CRITICAL", desc: "Fortinet OOB Write" },
  { id: "CVE-2024-1709", sev: "CRITICAL", desc: "ConnectWise Auth Bypass" },
  { id: "CVE-2023-46805", sev: "HIGH", desc: "Ivanti Auth Bypass" },
  { id: "CVE-2024-27198", sev: "CRITICAL", desc: "TeamCity Auth Bypass" },
  { id: "CVE-2024-6387", sev: "CRITICAL", desc: "OpenSSH Race Condition" },
  { id: "CVE-2024-4577", sev: "CRITICAL", desc: "PHP CGI Arg Injection" },
  { id: "CVE-2023-44487", sev: "HIGH", desc: "HTTP/2 Rapid Reset" },
  { id: "CVE-2024-23897", sev: "CRITICAL", desc: "Jenkins Path Traversal" },
  { id: "CVE-2024-21413", sev: "CRITICAL", desc: "Outlook RCE" },
];

const STATS = [
  { value: 112, suffix: "+", label: "Vulnerabilities Detected" },
  { value: 39, suffix: "", label: "Scanner Modules" },
  { value: 18, suffix: "", label: "AI Endpoints" },
  { value: 100, suffix: "", label: "Risk Score Tracked" },
];

const GLITCH_CHARS = "!<>-_\\/[]{}—=+*^?#ABCDEF0123456789";

// Matrix rain canvas
function MatrixRain() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    };
    resize();
    window.addEventListener("resize", resize);

    const cols = Math.floor(canvas.width / 14);
    const drops: number[] = Array(cols).fill(1);
    const chars = "アイウエオカキクケコサシスセソタチツテトナニヌネノ01アBCDEF<>{}[]01アBCDEF";

    let raf: number;
    let tick = 0;

    function draw() {
      tick++;
      if (tick % 2 !== 0) { raf = requestAnimationFrame(draw); return; }

      ctx!.fillStyle = "rgba(10,10,15,0.05)";
      ctx!.fillRect(0, 0, canvas!.width, canvas!.height);

      for (let i = 0; i < drops.length; i++) {
        const char = chars[Math.floor(Math.random() * chars.length)];
        const x = i * 14;
        const y = drops[i]! * 14;

        const progress = y / canvas!.height;
        if (progress < 0.4) {
          ctx!.fillStyle = `rgba(124,58,237,${0.12 + Math.random() * 0.06})`;
        } else {
          ctx!.fillStyle = `rgba(103,232,249,${0.06 + Math.random() * 0.04})`;
        }

        ctx!.font = "12px monospace";
        ctx!.fillText(char!, x, y);

        if (y > canvas!.height && Math.random() > 0.975) drops[i] = 0;
        drops[i]!++;
      }
      raf = requestAnimationFrame(draw);
    }

    raf = requestAnimationFrame(draw);
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", resize); };
  }, []);

  return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full opacity-40" style={{ pointerEvents: "none" }} />;
}

// Particle network canvas
function ParticleNetwork() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    };
    resize();
    window.addEventListener("resize", resize);

    const N = 55;
    const nodes = Array.from({ length: N }, () => ({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.35,
      vy: (Math.random() - 0.5) * 0.35,
      r: Math.random() * 2 + 1,
    }));

    let raf: number;
    function draw() {
      ctx!.clearRect(0, 0, canvas!.width, canvas!.height);

      for (const n of nodes) {
        n.x += n.vx; n.y += n.vy;
        if (n.x < 0 || n.x > canvas!.width) n.vx *= -1;
        if (n.y < 0 || n.y > canvas!.height) n.vy *= -1;
      }

      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i]!.x - nodes[j]!.x;
          const dy = nodes[i]!.y - nodes[j]!.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 130) {
            const alpha = (1 - dist / 130) * 0.15;
            ctx!.strokeStyle = `rgba(139,92,246,${alpha})`;
            ctx!.lineWidth = 0.8;
            ctx!.beginPath();
            ctx!.moveTo(nodes[i]!.x, nodes[i]!.y);
            ctx!.lineTo(nodes[j]!.x, nodes[j]!.y);
            ctx!.stroke();
          }
        }
      }

      for (const n of nodes) {
        ctx!.beginPath();
        ctx!.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx!.fillStyle = "rgba(167,139,250,0.5)";
        ctx!.fill();
      }

      raf = requestAnimationFrame(draw);
    }

    raf = requestAnimationFrame(draw);
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", resize); };
  }, []);

  return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full" style={{ pointerEvents: "none" }} />;
}

// Glitch text hook
function useGlitch(text: string, interval = 4000) {
  const [display, setDisplay] = useState(text);

  useEffect(() => {
    let timeout: ReturnType<typeof setTimeout>;
    let frame: ReturnType<typeof setTimeout>;
    let iteration = 0;

    function glitch() {
      const maxIter = text.length * 2;
      frame = setTimeout(() => {
        setDisplay(
          text.split("").map((char, idx) => {
            if (char === " ") return " ";
            if (idx < iteration / 2) return text[idx]!;
            return GLITCH_CHARS[Math.floor(Math.random() * GLITCH_CHARS.length)]!;
          }).join("")
        );
        iteration++;
        if (iteration < maxIter) glitch();
        else { setDisplay(text); iteration = 0; }
      }, 35);
    }

    timeout = setTimeout(() => { glitch(); }, interval);
    const loop = setInterval(() => {
      timeout = setTimeout(() => { glitch(); }, 0);
    }, interval);

    return () => { clearTimeout(timeout); clearTimeout(frame); clearInterval(loop); };
  }, [text, interval]);

  return display;
}

// Animated counter
function AnimatedCounter({ value, suffix }: { value: number; suffix: string }) {
  const [count, setCount] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(([entry]) => {
      if (entry?.isIntersecting && !started.current) {
        started.current = true;
        const duration = 1800;
        const start = performance.now();
        function tick(now: number) {
          const t = Math.min((now - start) / duration, 1);
          const eased = 1 - Math.pow(1 - t, 3);
          setCount(Math.floor(eased * value));
          if (t < 1) requestAnimationFrame(tick);
          else setCount(value);
        }
        requestAnimationFrame(tick);
      }
    }, { threshold: 0.5 });
    obs.observe(el);
    return () => obs.disconnect();
  }, [value]);

  return <div ref={ref} className="text-4xl font-black mb-1" style={{ color: "#a78bfa" }}>{count}{suffix}</div>;
}

// Typewriter terminal
function TypewriterTerminal() {
  const [visibleLines, setVisibleLines] = useState<number[]>([]);
  const [typingIdx, setTypingIdx] = useState(-1);

  useEffect(() => {
    const timers: ReturnType<typeof setTimeout>[] = [];
    TERMINAL_LINES.forEach((line, i) => {
      timers.push(setTimeout(() => {
        setVisibleLines(v => [...v, i]);
        setTypingIdx(i);
      }, line.delay));
    });
    return () => timers.forEach(clearTimeout);
  }, []);

  return (
    <div className="mt-16 max-w-3xl mx-auto rounded-2xl overflow-hidden shadow-2xl text-left relative z-10"
      style={{ border: "1px solid rgba(255,255,255,0.07)", background: "#0a0a12", boxShadow: "0 40px 80px rgba(0,0,0,0.7), 0 0 60px rgba(124,58,237,0.08)" }}>
      {/* Title bar */}
      <div className="flex items-center gap-2 px-4 py-3" style={{ borderBottom: "1px solid rgba(255,255,255,0.05)", background: "rgba(255,255,255,0.015)" }}>
        <div className="w-3 h-3 rounded-full" style={{ background: "rgba(239,68,68,0.7)" }} />
        <div className="w-3 h-3 rounded-full" style={{ background: "rgba(234,179,8,0.7)" }} />
        <div className="w-3 h-3 rounded-full" style={{ background: "rgba(34,197,94,0.7)" }} />
        <span className="ml-2 text-xs font-mono" style={{ color: "rgba(255,255,255,0.2)" }}>bug-finder-pro — scan engine v3.2.1</span>
        <div className="ml-auto flex items-center gap-1.5">
          <div className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "#4ade80" }} />
          <span className="text-xs font-mono" style={{ color: "rgba(74,222,128,0.6)" }}>LIVE</span>
        </div>
      </div>
      <div className="p-5 font-mono text-xs space-y-2 min-h-[180px]">
        {TERMINAL_LINES.map((line, i) => {
          if (!visibleLines.includes(i)) return null;
          const isTyping = typingIdx === i && i === TERMINAL_LINES.length - 1;
          return (
            <p key={i} className="flex items-center gap-2">
              <span style={{ color: line.iconColor, minWidth: 12 }}>{line.icon}</span>
              <span style={{ color: line.textColor ?? "rgba(255,255,255,0.45)" }}>{line.text}</span>
              {line.suffix && <span style={{ color: line.suffixColor }}>{line.suffix}</span>}
              {line.streaming && <span className="animate-pulse" style={{ color: "#67e8f9" }}>...</span>}
              {isTyping && !line.streaming && <span className="animate-pulse ml-0.5" style={{ color: "#a78bfa" }}>█</span>}
            </p>
          );
        })}
        {visibleLines.length === 0 && (
          <p className="flex items-center gap-2">
            <span style={{ color: "#a78bfa" }}>›</span>
            <span style={{ color: "rgba(255,255,255,0.2)" }}>Connecting to scan engine</span>
            <span className="animate-pulse" style={{ color: "#a78bfa" }}>█</span>
          </p>
        )}
      </div>
    </div>
  );
}

// CVE ticker
function CveTicker() {
  return (
    <div className="relative overflow-hidden py-2" style={{ borderTop: "1px solid rgba(255,255,255,0.04)", borderBottom: "1px solid rgba(255,255,255,0.04)", background: "rgba(0,0,0,0.3)" }}>
      <div className="flex gap-0" style={{ animation: "ticker 35s linear infinite", whiteSpace: "nowrap" }}>
        {[...CVE_TICKER, ...CVE_TICKER].map((cve, i) => (
          <span key={i} className="inline-flex items-center gap-2 px-6 text-xs font-mono">
            <span style={{ color: cve.sev === "CRITICAL" ? "#f87171" : "#facc15" }}>●</span>
            <span style={{ color: cve.sev === "CRITICAL" ? "#fca5a5" : "#fde047" }}>{cve.id}</span>
            <span style={{ color: "rgba(255,255,255,0.25)" }}>{cve.desc}</span>
            <span className="ml-2" style={{ color: "rgba(255,255,255,0.1)" }}>|</span>
          </span>
        ))}
      </div>
      <div className="absolute left-0 top-0 bottom-0 w-16 pointer-events-none" style={{ background: "linear-gradient(to right, #0a0a0f, transparent)" }} />
      <div className="absolute right-0 top-0 bottom-0 w-16 pointer-events-none" style={{ background: "linear-gradient(to left, #0a0a0f, transparent)" }} />
    </div>
  );
}

// Scan line overlay
function ScanLine() {
  return (
    <div className="fixed inset-0 pointer-events-none z-50 overflow-hidden" style={{ opacity: 0.025 }}>
      <div style={{ width: "100%", height: "2px", background: "rgba(103,232,249,0.8)", animation: "scanline 8s linear infinite", position: "absolute" }} />
    </div>
  );
}

export default function Landing() {
  const [, nav] = useLocation();
  const [hoveredFeature, setHoveredFeature] = useState<number | null>(null);
  const [owaspPulse, setOwaspPulse] = useState<number | null>(null);
  const { data: user } = useGetMe();

  const glitchLine1 = useGlitch("Find Bugs.");
  const glitchLine2 = useGlitch("Before They Find You.", 5500);

  useEffect(() => {
    if (user) nav("/dashboard");
  }, [user, nav]);

  // OWASP threat pulse — randomly activates one card
  useEffect(() => {
    const loop = setInterval(() => {
      const idx = Math.floor(Math.random() * OWASP.length);
      setOwaspPulse(idx);
      setTimeout(() => setOwaspPulse(null), 900);
    }, 1800);
    return () => clearInterval(loop);
  }, []);

  async function handleDemo() {
    try {
      const r = await fetch("/api/auth/demo", { method: "POST", credentials: "include" });
      if (r.ok) nav("/dashboard");
    } catch {}
  }

  return (
    <>
      <style>{`
        @keyframes ticker {
          0% { transform: translateX(0); }
          100% { transform: translateX(-50%); }
        }
        @keyframes scanline {
          0% { top: -2px; }
          100% { top: 100%; }
        }
        @keyframes float {
          0%, 100% { transform: translateY(0px); }
          50% { transform: translateY(-8px); }
        }
        @keyframes borderPulse {
          0%, 100% { box-shadow: 0 0 0 0 rgba(124,58,237,0); }
          50% { box-shadow: 0 0 0 4px rgba(124,58,237,0.15); }
        }
        @keyframes hexPulse {
          0% { opacity: 0.03; }
          50% { opacity: 0.07; }
          100% { opacity: 0.03; }
        }
        .feature-card:hover .scan-beam {
          opacity: 1;
          animation: none;
        }
        .feature-card .scan-beam {
          opacity: 0;
          transition: opacity 0.3s;
          position: absolute;
          inset: 0;
          border-radius: inherit;
          background: conic-gradient(from 0deg, transparent 0deg, rgba(139,92,246,0.08) 60deg, transparent 120deg);
          animation: spin 3s linear infinite;
          pointer-events: none;
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        .glow-btn:hover {
          box-shadow: 0 8px 40px rgba(124,58,237,0.55) !important;
          transform: translateY(-1px);
        }
        .glow-btn { transition: all 0.2s ease; }
      `}</style>

      <ScanLine />

      <div className="min-h-screen text-white font-sans overflow-x-hidden" style={{ background: "#0a0a0f" }}>
        {/* Nav */}
        <nav className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-8 py-4 backdrop-blur-xl"
          style={{ borderBottom: "1px solid rgba(255,255,255,0.05)", background: "rgba(10,10,15,0.9)" }}>
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: "#7c3aed", boxShadow: "0 0 20px rgba(124,58,237,0.5), 0 0 40px rgba(124,58,237,0.15)" }}>
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
            <button onClick={() => nav("/login")} className="px-4 py-2 text-sm transition-colors hover:text-white" style={{ color: "rgba(255,255,255,0.6)" }}>
              Sign In
            </button>
            <button onClick={() => nav("/login")} className="glow-btn px-4 py-2 text-sm font-medium rounded-lg text-white" style={{ background: "#7c3aed", boxShadow: "0 4px 15px rgba(124,58,237,0.35)" }}>
              Start Free Scan
            </button>
          </div>
        </nav>

        {/* CVE Ticker */}
        <div className="fixed top-[65px] left-0 right-0 z-40">
          <CveTicker />
        </div>

        {/* Hero */}
        <section className="relative pt-40 pb-24 px-8 text-center overflow-hidden" style={{ minHeight: "100vh" }}>
          {/* Matrix Rain */}
          <div className="absolute inset-0 overflow-hidden">
            <MatrixRain />
          </div>
          {/* Particle network */}
          <div className="absolute inset-0">
            <ParticleNetwork />
          </div>
          {/* Radial glow */}
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <div className="w-[800px] h-[800px] rounded-full" style={{ background: "rgba(124,58,237,0.06)", filter: "blur(140px)" }} />
          </div>

          {/* Hex grid SVG overlay */}
          <div className="absolute inset-0 pointer-events-none overflow-hidden" style={{ animation: "hexPulse 6s ease-in-out infinite" }}>
            <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <pattern id="hex" x="0" y="0" width="60" height="52" patternUnits="userSpaceOnUse">
                  <polygon points="30,2 58,17 58,47 30,62 2,47 2,17" fill="none" stroke="rgba(139,92,246,0.08)" strokeWidth="1" />
                </pattern>
              </defs>
              <rect width="100%" height="100%" fill="url(#hex)" />
            </svg>
          </div>

          <div className="relative z-10">
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium mb-8"
              style={{ border: "1px solid rgba(139,92,246,0.4)", background: "rgba(139,92,246,0.1)", color: "#c4b5fd", animation: "borderPulse 3s ease-in-out infinite" }}>
              <div className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "#a78bfa" }} />
              AI-Powered Security Operations Platform
              <span className="ml-1 font-mono text-[10px]" style={{ color: "rgba(167,139,250,0.6)" }}>v3.2.1</span>
            </div>

            <h1 className="text-5xl md:text-7xl font-black tracking-tight mb-6 leading-none">
              <span className="font-mono" style={{ color: "rgba(255,255,255,0.95)", letterSpacing: "-0.02em" }}>{glitchLine1}</span>
              <br />
              <span style={{ background: "linear-gradient(90deg, #a78bfa, #67e8f9, #a78bfa)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundSize: "200% auto", animation: "shimmer 4s linear infinite" }}>
                {glitchLine2}
              </span>
            </h1>

            <style>{`
              @keyframes shimmer {
                0% { background-position: 0% center; }
                100% { background-position: 200% center; }
              }
            `}</style>

            <p className="text-lg max-w-2xl mx-auto mb-10 leading-relaxed" style={{ color: "rgba(255,255,255,0.4)" }}>
              Enterprise-grade vulnerability scanning with real-time AI analysis, OWASP Top 10 coverage,
              SLA enforcement, and one-click GitHub issue creation — all in one platform.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <button
                onClick={() => nav("/login")}
                className="glow-btn group flex items-center gap-2 px-6 py-3.5 text-white rounded-xl font-semibold"
                style={{ background: "#7c3aed", boxShadow: "0 8px 30px rgba(124,58,237,0.4)" }}
              >
                Launch Your First Scan
                <ArrowRight size={16} className="group-hover:translate-x-0.5 transition-transform" />
              </button>
              <button
                onClick={handleDemo}
                className="flex items-center gap-2 px-6 py-3.5 rounded-xl font-medium transition-all hover:text-white hover:border-white/20"
                style={{ border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.6)" }}
              >
                <Terminal size={16} />
                Continue as Demo
              </button>
            </div>
          </div>

          <TypewriterTerminal />
        </section>

        {/* Stats */}
        <section id="coverage" className="py-16 px-8" style={{ borderTop: "1px solid rgba(255,255,255,0.05)", borderBottom: "1px solid rgba(255,255,255,0.05)", background: "rgba(0,0,0,0.2)" }}>
          <div className="max-w-4xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
            {STATS.map(s => (
              <div key={s.label}>
                <AnimatedCounter value={s.value} suffix={s.suffix} />
                <div className="text-sm" style={{ color: "rgba(255,255,255,0.3)" }}>{s.label}</div>
              </div>
            ))}
          </div>
        </section>

        {/* Features */}
        <section id="features" className="py-24 px-8 relative overflow-hidden">
          <div className="absolute inset-0 pointer-events-none">
            <ParticleNetwork />
          </div>
          <div className="max-w-6xl mx-auto relative z-10">
            <div className="text-center mb-16">
              <div className="text-xs font-semibold uppercase tracking-widest mb-3 font-mono" style={{ color: "#a78bfa" }}>
                <span style={{ color: "rgba(167,139,250,0.4)" }}>// </span>Platform Features
              </div>
              <h2 className="text-4xl font-bold text-white mb-4">Everything you need to secure your stack</h2>
              <p className="max-w-xl mx-auto" style={{ color: "rgba(255,255,255,0.3)" }}>From automated scanning to AI remediation — one platform for your entire security workflow.</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
              {FEATURES.map((f, i) => (
                <div
                  key={f.title}
                  className="feature-card p-6 rounded-2xl transition-all cursor-default relative overflow-hidden"
                  style={{
                    border: hoveredFeature === i ? `1px solid ${f.color}30` : "1px solid rgba(255,255,255,0.05)",
                    background: hoveredFeature === i ? `${f.color}08` : "rgba(255,255,255,0.015)",
                    transform: hoveredFeature === i ? "translateY(-2px)" : "none",
                    boxShadow: hoveredFeature === i ? `0 20px 40px ${f.color}10` : "none",
                    transition: "all 0.25s ease",
                  }}
                  onMouseEnter={() => setHoveredFeature(i)}
                  onMouseLeave={() => setHoveredFeature(null)}
                >
                  <div className="scan-beam" />
                  <div
                    className="w-10 h-10 rounded-xl flex items-center justify-center mb-4 transition-all"
                    style={{
                      background: `${f.color}18`,
                      boxShadow: hoveredFeature === i ? `0 0 25px ${f.color}35` : "none",
                      animation: hoveredFeature === i ? "float 2s ease-in-out infinite" : "none",
                    }}
                  >
                    <f.icon size={20} style={{ color: f.color }} />
                  </div>
                  <h3 className="font-semibold text-white mb-2">{f.title}</h3>
                  <p className="text-sm leading-relaxed" style={{ color: "rgba(255,255,255,0.35)" }}>{f.desc}</p>
                  {hoveredFeature === i && (
                    <div className="absolute bottom-3 right-3 text-xs font-mono" style={{ color: `${f.color}60` }}>
                      ACTIVE
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* OWASP */}
        <section id="owasp" className="py-20 px-8" style={{ background: "rgba(0,0,0,0.25)", borderTop: "1px solid rgba(255,255,255,0.05)", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-12">
              <div className="text-xs font-semibold uppercase tracking-widest mb-3 font-mono" style={{ color: "#67e8f9" }}>
                <span style={{ color: "rgba(103,232,249,0.4)" }}>// </span>Compliance Coverage
              </div>
              <h2 className="text-3xl font-bold text-white mb-3">Full OWASP Top 10 Coverage</h2>
              <p style={{ color: "rgba(255,255,255,0.3)" }}>Automated detection and classification across all 10 OWASP categories.</p>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              {OWASP.map((cat, i) => (
                <div
                  key={cat}
                  className="flex items-center gap-2 px-3 py-2.5 rounded-xl transition-all"
                  style={{
                    background: owaspPulse === i ? "rgba(239,68,68,0.08)" : "rgba(255,255,255,0.02)",
                    border: owaspPulse === i ? "1px solid rgba(239,68,68,0.35)" : "1px solid rgba(255,255,255,0.05)",
                    boxShadow: owaspPulse === i ? "0 0 20px rgba(239,68,68,0.12)" : "none",
                    transition: "all 0.2s ease",
                  }}
                >
                  <CheckCircle2 size={14} style={{ color: owaspPulse === i ? "#f87171" : "#67e8f9", flexShrink: 0, transition: "color 0.2s" }} />
                  <span className="text-xs leading-tight" style={{ color: owaspPulse === i ? "#fca5a5" : "rgba(255,255,255,0.5)", transition: "color 0.2s" }}>{cat}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="py-24 px-8 text-center relative overflow-hidden">
          <div className="absolute inset-0 pointer-events-none">
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="w-[600px] h-[600px] rounded-full" style={{ background: "rgba(124,58,237,0.07)", filter: "blur(120px)" }} />
            </div>
            <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style={{ opacity: 0.04 }}>
              <defs>
                <pattern id="hex2" x="0" y="0" width="60" height="52" patternUnits="userSpaceOnUse">
                  <polygon points="30,2 58,17 58,47 30,62 2,47 2,17" fill="none" stroke="rgba(139,92,246,1)" strokeWidth="1" />
                </pattern>
              </defs>
              <rect width="100%" height="100%" fill="url(#hex2)" />
            </svg>
          </div>
          <div className="relative max-w-2xl mx-auto">
            <div className="flex items-center justify-center gap-1 mb-6">
              {[...Array(5)].map((_, i) => <Star key={i} size={16} style={{ color: "#facc15", fill: "#facc15" }} />)}
            </div>
            <h2 className="text-4xl font-bold text-white mb-4">Start securing your applications today</h2>
            <p className="mb-10" style={{ color: "rgba(255,255,255,0.35)" }}>Join security teams using Bug Finder Pro to detect, prioritize, and remediate vulnerabilities faster.</p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <button
                onClick={() => nav("/login")}
                className="glow-btn group flex items-center gap-2 px-8 py-4 text-white rounded-xl font-semibold text-lg"
                style={{ background: "#7c3aed", boxShadow: "0 8px 30px rgba(124,58,237,0.35)" }}
              >
                Get Started Free
                <ChevronRight size={18} className="group-hover:translate-x-0.5 transition-transform" />
              </button>
              <button
                onClick={handleDemo}
                className="px-8 py-4 rounded-xl font-medium text-lg transition-all hover:text-white hover:border-white/20"
                style={{ border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.45)" }}
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
            <span className="font-semibold font-mono" style={{ color: "rgba(255,255,255,0.4)" }}>Bug Finder Pro</span>
          </div>
          <p className="text-xs font-mono" style={{ color: "rgba(255,255,255,0.15)" }}>© 2026 Bug Finder Pro. Security Operations Platform.</p>
          <div className="flex items-center gap-2 text-xs font-mono" style={{ color: "rgba(255,255,255,0.2)" }}>
            <Activity size={12} style={{ color: "#4ade80" }} />
            <span style={{ color: "#4ade80" }}>All systems operational</span>
          </div>
        </footer>
      </div>
    </>
  );
}
