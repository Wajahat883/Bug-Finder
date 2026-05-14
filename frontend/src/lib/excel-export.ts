/**
 * Excel / CSV Export utility — uses SheetJS (xlsx).
 * Falls back to CSV download if xlsx is not installed.
 */

interface ExportRow {
  [key: string]: string | number | boolean | null | undefined;
}

function toCsv(headers: string[], rows: ExportRow[]): string {
  const escape = (v: unknown) => {
    const s = v == null ? "" : String(v);
    return s.includes(",") || s.includes('"') || s.includes("\n")
      ? `"${s.replace(/"/g, '""')}"`
      : s;
  };
  const lines = [headers.map(escape).join(",")];
  for (const row of rows) {
    lines.push(headers.map(h => escape(row[h])).join(","));
  }
  return lines.join("\n");
}

function downloadBlob(content: string | Uint8Array, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export async function exportToExcel(
  data: ExportRow[],
  filename = "export",
  sheetName = "Sheet1"
): Promise<void> {
  try {
    // Dynamic import — works if xlsx is installed
    const XLSX = await import("xlsx");
    const ws = XLSX.utils.json_to_sheet(data);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, sheetName);

    // Auto-fit column widths
    const cols = Object.keys(data[0] ?? {});
    ws["!cols"] = cols.map(key => ({
      wch: Math.min(
        Math.max(key.length, ...data.map(r => String(r[key] ?? "").length)),
        50
      ),
    }));

    const buf = XLSX.write(wb, { type: "array", bookType: "xlsx" });
    downloadBlob(new Uint8Array(buf), `${filename}.xlsx`, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  } catch {
    // Fallback to CSV if xlsx not available
    exportToCsv(data, filename);
  }
}

export function exportToCsv(data: ExportRow[], filename = "export"): void {
  if (data.length === 0) return;
  const headers = Object.keys(data[0]);
  const csv = toCsv(headers, data);
  downloadBlob(csv, `${filename}.csv`, "text/csv;charset=utf-8;");
}

// ── Finding-specific export helpers ──────────────────────────────────────────

export interface FindingExportRow {
  id: string;
  title: string;
  severity: string;
  cvss_score: number | null;
  cwe_id: string;
  category: string;
  endpoint: string;
  scanner_name: string;
  validation_status: string;
  triage_status: string;
  compliance_tags: string;
  created_at: string;
}

export function prepareFindingsForExport(findings: Record<string, unknown>[]): FindingExportRow[] {
  return findings.map(f => ({
    id: String(f["id"] ?? f["_id"] ?? ""),
    title: String(f["title"] ?? ""),
    severity: String(f["severity"] ?? ""),
    cvss_score: f["cvss_score"] != null ? Number(f["cvss_score"]) : null,
    cwe_id: String(f["cwe_id"] ?? ""),
    category: String(f["category"] ?? ""),
    endpoint: String(f["endpoint"] ?? ""),
    scanner_name: String(f["scanner_name"] ?? ""),
    validation_status: String(f["validation_status"] ?? ""),
    triage_status: String(f["triage_status"] ?? "open"),
    compliance_tags: Array.isArray(f["compliance_tags"]) ? (f["compliance_tags"] as string[]).join("; ") : "",
    created_at: f["created_at"] ? new Date(f["created_at"] as string).toISOString().split("T")[0] : "",
  }));
}
