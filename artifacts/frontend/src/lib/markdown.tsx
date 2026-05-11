import React from "react";

// Renders a useful subset of markdown without external dependencies.
// Handles: H1/H2/H3, bold, italic, inline code, fenced code blocks,
// unordered lists, ordered lists, checkbox lists, horizontal rules, paragraphs.
export function MarkdownContent({ content, className = "" }: { content: string; className?: string }) {
  const lines = content.split("\n");
  const elements: React.ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block
    if (line.startsWith("```")) {
      const lang = line.slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      elements.push(
        <pre key={`code-${i}`} className="bg-black/40 border border-border rounded-lg p-4 overflow-x-auto text-xs font-mono my-3">
          <code className={lang ? `language-${lang}` : ""}>{codeLines.join("\n")}</code>
        </pre>
      );
      i++; // skip closing ```
      continue;
    }

    // Headers
    const h3m = line.match(/^### (.+)/);
    const h2m = line.match(/^## (.+)/);
    const h1m = line.match(/^# (.+)/);
    if (h1m) { elements.push(<h1 key={i} className="text-lg font-bold mt-5 mb-2 text-foreground">{inlineFormat(h1m[1])}</h1>); i++; continue; }
    if (h2m) { elements.push(<h2 key={i} className="text-base font-bold mt-4 mb-2 text-violet-300">{inlineFormat(h2m[1])}</h2>); i++; continue; }
    if (h3m) { elements.push(<h3 key={i} className="text-sm font-semibold mt-3 mb-1.5 text-violet-200">{inlineFormat(h3m[1])}</h3>); i++; continue; }

    // Horizontal rule
    if (line.match(/^---+$/) || line.match(/^\*\*\*+$/)) {
      elements.push(<hr key={i} className="border-border my-3" />);
      i++; continue;
    }

    // Checkbox list items (before unordered list check)
    if (line.match(/^- \[[ xX]\] /)) {
      const items: React.ReactNode[] = [];
      while (i < lines.length && lines[i].match(/^- \[[ xX]\] /)) {
        const checked = /^- \[[xX]\] /.test(lines[i]);
        items.push(
          <div key={i} className="flex items-start gap-2 text-sm my-0.5">
            <span className={`mt-0.5 text-xs shrink-0 ${checked ? "text-green-400" : "text-muted-foreground"}`}>{checked ? "✓" : "○"}</span>
            <span>{inlineFormat(lines[i].replace(/^- \[[xX ]\] /, ""))}</span>
          </div>
        );
        i++;
      }
      elements.push(<div key={`cb-${i}`} className="my-2 space-y-0.5">{items}</div>);
      continue;
    }

    // Unordered list
    if (line.match(/^[-*+] /)) {
      const items: React.ReactNode[] = [];
      while (i < lines.length && lines[i].match(/^[-*+] /)) {
        items.push(<li key={i} className="ml-1">{inlineFormat(lines[i].slice(2))}</li>);
        i++;
      }
      elements.push(<ul key={`ul-${i}`} className="list-disc list-inside space-y-0.5 my-2 text-sm">{items}</ul>);
      continue;
    }

    // Ordered list
    if (line.match(/^\d+\. /)) {
      const items: React.ReactNode[] = [];
      while (i < lines.length && lines[i].match(/^\d+\. /)) {
        items.push(<li key={i} className="ml-1">{inlineFormat(lines[i].replace(/^\d+\. /, ""))}</li>);
        i++;
      }
      elements.push(<ol key={`ol-${i}`} className="list-decimal list-inside space-y-0.5 my-2 text-sm">{items}</ol>);
      continue;
    }

    // Empty line → spacing
    if (line.trim() === "") {
      elements.push(<div key={`sp-${i}`} className="h-1.5" />);
      i++; continue;
    }

    // Regular paragraph
    elements.push(<p key={i} className="text-sm leading-relaxed">{inlineFormat(line)}</p>);
    i++;
  }

  return <div className={`space-y-0.5 ${className}`}>{elements}</div>;
}

function inlineFormat(text: string): React.ReactNode {
  // Split on bold (**x**), inline code (`x`), italic (*x*)
  const parts = text.split(/(\*\*[^*\n]+\*\*|`[^`\n]+`|\*[^*\n]+\*)/g);
  return (
    <>
      {parts.map((part, i) => {
        if (part.startsWith("**") && part.endsWith("**") && part.length > 4) {
          return <strong key={i} className="font-semibold text-foreground">{part.slice(2, -2)}</strong>;
        }
        if (part.startsWith("`") && part.endsWith("`") && part.length > 2) {
          return <code key={i} className="bg-black/30 text-violet-300 px-1 py-0.5 rounded text-xs font-mono">{part.slice(1, -1)}</code>;
        }
        if (part.startsWith("*") && part.endsWith("*") && part.length > 2) {
          return <em key={i} className="italic">{part.slice(1, -1)}</em>;
        }
        return <React.Fragment key={i}>{part}</React.Fragment>;
      })}
    </>
  );
}
