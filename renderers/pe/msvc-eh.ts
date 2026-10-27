import type { MsvcEhAnalysis, MsvcEhRecord } from "../../analyzers/pe/msvc-eh/types.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import { escapeHtml } from "../../html-utils.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import { renderPeDiagnostics } from "./diagnostics.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";

const rvaText = (rva: number): string => `0x${rva.toString(16)}`;

const recordFormat = (record: MsvcEhRecord): string =>
  record.functionInfo ? `FH${record.functionInfo.version}` : record.registration ?? "SEH";

const metadataAddress = (record: MsvcEhRecord): string => {
  if (record.functionInfo) return rvaText(record.functionInfo.rva);
  return record.scopeTableRva !== undefined ? rvaText(record.scopeTableRva) : "SafeSEH entry";
};

const recordCounts = (record: MsvcEhRecord): string[] => {
  if (record.registration) return ["Not decoded", "Not decoded", "Not decoded"];
  if (record.scopes) return ["Not encoded", String(record.scopes.length), "Not encoded"];
  return [String(record.functionInfo.unwindActions.length), String(record.functionInfo.tryBlocks.length),
    String(record.functionInfo.tryBlocks.reduce((count, block) => count + block.handlers.length, 0))];
};

const recordCells = (record: MsvcEhRecord): string[] => [
  recordFormat(record),
  record.functionRvas.map(rvaText).join(", ") || "Unresolved", rvaText(record.handlerRva),
  metadataAddress(record), ...recordCounts(record),
  record.evidence
];

const recordDetails = (record: MsvcEhRecord): string => {
  const handlers = record.functionInfo?.tryBlocks.flatMap(block => block.handlers) ?? [];
  if (!handlers.length) return "";
  const rows = handlers.map(handler => `<tr><td class="peNumeric">${rvaText(handler.handlerRva)}</td>` +
    `<td class="peNumeric">${handler.typeDescriptorRva ? rvaText(handler.typeDescriptorRva) : "catch (...)"}</td>` +
    `<td class="peNumeric">${handler.continuationRvas.map(rvaText).join(", ") || "Not encoded"}</td></tr>`).join("");
  return `<tr><td colspan="8"><details><summary>Verified catch handlers</summary>` +
    `<div class="tableWrap"><table><thead><tr><th class="peNumeric">Handler RVA</th>` +
    `<th class="peNumeric">TypeDescriptor RVA</th><th class="peNumeric">Continuation RVAs</th>` +
    `</tr></thead><tbody>${rows}</tbody></table>` +
    `</div></details></td></tr>`;
};

const createTable = (analysis: MsvcEhAnalysis): PagedSortableTableModel => ({
  id: "pe-msvc-eh", rowCount: analysis.records.length, pageSize: 50, // Presentation page size, not an ABI limit.
  columns: ["Format", "Function RVAs", "Handler RVA", "Metadata RVA", "Unwind states", "Try/scopes",
    "Catches", "Evidence"].map((label, index) => ({ label,
    ...(index > 0 && index < 7 ? { className: "peNumeric" } : {}) })),
  rowAt: index => {
    const record = analysis.records[index];
    return record ? { cells: recordCells(record).map((value, column) => ({ html: escapeHtml(value),
      ...(column > 0 && column < 7 ? { className: "peNumeric" } : {}) })),
      additionalRowsHtml: recordDetails(record) } : null;
  },
  sortValueAt: (index, column) => {
    const record = analysis.records[index];
    return record ? recordCells(record)[column] ?? "" : "";
  }
});

export const getMsvcEhTableModel = (
  pe: PeWindowsParseResult, tableId: string
): PagedSortableTableModel | null => tableId === "pe-msvc-eh" && pe.msvcEh ? createTable(pe.msvcEh) : null;

export const renderMsvcEh = (analysis: MsvcEhAnalysis, out: string[]): void => {
  out.push(renderPeSectionStart("Microsoft-compatible exception handling",
    `${analysis.records.length} verified record(s)`));
  out.push(`<p class="smallNote">Only validated metadata is listed. Coverage depends on architecture, ` +
    `metadata version and available handler evidence. Unlisted or unresolved records do not establish ` +
    `the absence of exception handling or identify the compiler.</p>`);
  if (analysis.records.length) out.push(renderAutoPagedSortableTable(createTable(analysis)));
  if (analysis.warnings.length) out.push(renderPeDiagnostics("Microsoft EH diagnostics", analysis.warnings));
  out.push(renderPeSectionEnd());
};
