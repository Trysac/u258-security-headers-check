import type { Finding } from "./types.js";

/**
 * Formats a list of findings as plain text or JSON.
 *
 * @param findings - The findings to format.
 * @param format - `'text'` for one line per finding, `'json'` for a JSON array.
 * @returns The formatted report.
 */
export function formatReport(findings: Finding[], format: "text" | "json"): string {
  if (format === "json") {
    return JSON.stringify(findings);
  }
  if (findings.length === 0) {
    return "no findings";
  }
  return findings.map((f) => `${f.severity} ${f.id} ${f.message}`).join("\n");
}
