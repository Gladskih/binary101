import type { Amd64PrologReport, Amd64PrologFinding }
  from "../../analyzers/pe/exception/amd64/prolog-types.js";
import { escapeHtmlText, renderDefinitionRow } from "../../html-utils.js";
import { hex } from "../../binary-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel }
  from "../paged-sortable-table.js";
import { renderUnwindCounts } from "./unwind-inventories.js";

const limitationLabels: Record<string, string> = {
  "chained-unwind": "Chained unwind context",
  "entry-unwind-state": "Unwind state inherited at entry",
  "machine-frame": "Hardware machine frame",
  "stack-register-save": "RSP saved as a register",
  "unwind-version": "Unsupported unwind version",
  "invalid-unwind": "Incomplete or unsupported unwind metadata",
  "unwind-operation-range": "Unwind operation offset outside the recorded prolog",
  "undecodable-instruction": "Instruction could not be decoded",
  "unreadable-code": "Prolog bytes unavailable",
  "code-read-failed": "Code read failed",
  "unknown-stack-effect": "Stack adjustment not resolved",
  "unknown-register-value": "Saved register value not resolved",
  "unknown-saved-value": "Stack save value not resolved",
  "control-flow": "Control flow leaves the supported straight-line path",
  "stack-restoration": "Stack restoration within the recorded prolog",
  "epilog-in-prolog": "Restored epilog or tail transfer within the recorded prolog",
  "epilog-state-unknown": "Epilog state or lookahead incomplete",
  "function-end": "Counterexample falls at the exclusive pdata range end",
  "prolog-boundary": "Recorded prolog boundary inside an instruction",
  "disassembler-unavailable": "Disassembler could not be loaded",
  "invalid-function-range": "Invalid function range"
};

const describeLimitations = (reasons: string[]): string => reasons
  .map(reason => limitationLabels[reason] ?? reason).join("; ");

const assertion = (finding: Amd64PrologFinding): string => finding.issues.map(issue =>
  `<div>+${issue.offset}: ${escapeHtmlText(issue.expected ?? "Unwind instruction boundary")}</div>`
).join("");

const observed = (finding: Amd64PrologFinding): string => finding.issues.map(issue =>
  `<div>${escapeHtmlText(issue.actual ??
    (issue.code === "operation-boundary" ? "No instruction ends at this offset" :
      issue.code === "prolog-size" ? "Prolog extends past the pdata range" : "Unwind state differs"))}</div>`
).join("") + (finding.limitations.length
  ? `<p class="smallNote">Partial check: ${escapeHtmlText(describeLimitations(finding.limitations))}</p>` : "");

export const getPrologValidationTableModel = (report: Amd64PrologReport | undefined,
  tableId: string): PagedSortableTableModel | null => {
  if (!report?.findings.length || tableId !== "pe-prolog-validation") return null;
  return {
    id: tableId, pageSize: 50, rowCount: report.findings.length,
    columns: [{ label: "Function RVA", className: "peNumeric" },
      { label: "UNWIND_INFO RVA", className: "peNumeric" },
      { label: "Unwind assertion" }, { label: "Observed" }],
    rowAt: index => {
      const finding = report.findings[index];
      return finding ? { cells: [
        { html: `<button type="button" class="peEntrypointJump" ` +
          `data-pe-special-rva="${finding.beginRva}" ` +
          `aria-label="Disassemble at RVA ${hex(finding.beginRva, 8)}">` +
          `${hex(finding.beginRva, 8)}</button>`, className: "peNumeric" },
        { html: hex(finding.unwindInfoRva, 8), className: "peNumeric" },
        { html: assertion(finding) }, { html: observed(finding) }
      ] } : null;
    },
    sortValueAt: (index, column) => {
      const finding = report.findings[index];
      return finding ? [String(finding.beginRva), String(finding.unwindInfoRva),
        finding.issues.map(issue => issue.expected ?? issue.code).join(" "),
        finding.issues.map(issue => issue.actual ?? issue.code).join(" ")][column] ?? "" : "";
    },
    searchValueAt: index => {
      const finding = report.findings[index];
      return finding ? `${hex(finding.beginRva, 8)} ${hex(finding.unwindInfoRva, 8)} ` +
        finding.issues.map(issue => `${issue.code} ${issue.expected ?? ""} ${issue.actual ?? ""}`).join(" ") : "";
    }
  };
};

export const renderPrologValidation = (report: Amd64PrologReport): string => {
  const table = getPrologValidationTableModel(report, "pe-prolog-validation");
  const unverified = Object.values(report.unverifiedCounts).reduce((sum, count) => sum + count, 0);
  return `<section><h4>x64 prolog validation</h4>` +
    `<p class="smallNote">Checks stored code against unwind state at instruction boundaries ` +
    `in supported x64 v1/v2 prologs. Coverage is reported separately for unsupported paths.</p>` +
    `<dl class="peExceptionStats">` +
    renderDefinitionRow("Prologs with matching unwind state", String(report.matchedCount)) +
    renderDefinitionRow("Prologs with discrepancies", String(report.findings.length)) +
    renderDefinitionRow("Prologs not fully checked", String(unverified)) + `</dl>` +
    renderUnwindCounts("Reasons for incomplete prolog checks", "Reason", Object.fromEntries(
      Object.entries(report.unverifiedCounts).map(([reason, count]) =>
        [limitationLabels[reason] ?? reason, count]))) +
    (table ? renderAutoPagedSortableTable(table) : "") + `</section>`;
};
