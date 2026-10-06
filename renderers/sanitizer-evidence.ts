import type { SanitizerEvidence } from "../analyzers/sanitizers/types.js";
import { escapeHtml } from "../html-utils.js";

const EVIDENCE_LABELS: Readonly<Record<SanitizerEvidence["kind"], string>> = {
  dependency: "Runtime dependency", reference: "ABI reference",
  definition: "Runtime ABI definition", "build-setting": "Recorded build setting"
};

export const renderSanitizerEvidence = (evidence: readonly SanitizerEvidence[]): string => {
  const explanation = `<p class="smallNote">These are file-level clues. A runtime dependency ` +
    `or ABI definition does not prove that its checks are enabled or that every function ` +
    `is instrumented. Bundled runtimes may expose several sanitizers. ` +
    `Error reports are produced during execution.</p>`;
  if (!evidence.length) return explanation + `<p class="smallNote dim">` +
    `No supported sanitizer evidence was found. Stripped, renamed or trap-only ` +
    `instrumentation may be invisible; this does not establish absence of sanitizers.</p>`;
  return explanation + `<div class="tableWrap"><table class="table">` +
    `<thead><tr><th scope="col">Tool</th><th scope="col">Evidence kind</th>` +
    `<th scope="col">Source</th><th scope="col">Name / setting</th></tr></thead><tbody>` +
    evidence.map(row => `<tr><td>${escapeHtml(row.tool)}</td>` +
      `<td>${EVIDENCE_LABELS[row.kind]}</td><td>${escapeHtml(row.source)}</td>` +
      `<td><code>${escapeHtml(row.name)}</code></td></tr>`).join("") +
    `</tbody></table></div>` + (evidence.some(row => row.tool === "SanitizerCoverage")
      ? `<p class="smallNote">SanitizerCoverage is coverage instrumentation, ` +
        `often used for fuzzing; it is not itself an error detector.</p>` : "");
};
