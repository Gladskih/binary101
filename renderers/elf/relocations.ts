import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";
import { escapeHtml } from "../../html-utils.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import type { PagedSortableTableModel } from "../../ui/paged-sortable-table-state.js";
import { summarizeElfRelocations } from "./relocation-summary.js";
import type { ElfRelocationSummary, ElfRelocationSummaryKind } from "./relocation-summary.js";
import { getElfSymbolDisplayName } from "../../analyzers/elf/symbol-names.js";
import { renderSymbolName } from "../symbol-name.js";

const labels = { types: "Relocation type", formats: "Encoding", targets: "Target section", symbols: "Referenced symbol" };
const tableId = (kind: ElfRelocationSummaryKind): string =>
  kind === "types" ? "elf-relocations" : `elf-relocations-${kind}`;

export const createElfRelocationSummaryModel = (
  summary: ElfRelocationSummary, kind: ElfRelocationSummaryKind
): PagedSortableTableModel => {
  const rows = summary[kind];
  const total = summary.types.reduce((sum, row) => sum + row.count, 0);
  const values = (index: number): string[] => {
    const row = rows[index];
    return row ? [row.label, row.detail, String(row.count), `${(100 * row.count / total).toFixed(1)}%`] : [];
  };
  return { id: tableId(kind), pageSize: 100, rowCount: rows.length,
    columns: [labels[kind], "Meaning", "Records", "Share of all relocations"].map((label, index) => ({
      label, className: index >= 2 ? "peNumeric" : ""
    })),
    rowAt: index => rows[index] ? { cells: values(index).map((value, column) => ({
      html: column === 0 && rows[index]!.symbol?.name ?
        renderSymbolName(value, getElfSymbolDisplayName(rows[index]!.symbol!)) : escapeHtml(value),
      sortValue: column === 3 ? String(rows[index]!.count) : value,
      className: column >= 2 ? "peNumeric" : ""
    })) } : null,
    sortValueAt: (index, column) => column === 3 ? String(rows[index]?.count ?? "") : values(index)[column] ?? ""
  };
};

export const createElfRelocationTableModel = (elf: ElfParseResult): PagedSortableTableModel =>
  createElfRelocationSummaryModel(summarizeElfRelocations(elf), "types");

export const getElfRelocationSummaryModel = (elf: ElfParseResult, id: string): PagedSortableTableModel | null => {
  const kind = (Object.keys(labels) as ElfRelocationSummaryKind[]).find(kind => tableId(kind) === id);
  return kind && elf.relocations ? createElfRelocationSummaryModel(summarizeElfRelocations(elf), kind) : null;
};

export const renderElfRelocations = (elf: ElfParseResult, out: string[]): void => {
  const relocations = elf.relocations;
  if (!relocations) return;
  const summary = summarizeElfRelocations(elf);
  out.push(renderElfSectionStart(`Relocations (${relocations.entries.length})`));
  out.push(`<p>${relocations.entries.length} relocation records in ${relocations.tables.length} tables; ` +
    `${summary.symbols.length} distinct referenced symbols.</p>`);
  out.push(`<p class="smallNote">Counts describe linker/loader work, not executed instructions. ` +
    `Undefined symbols require lookup; their providers and runtime addresses are not inferred. ` +
    `REL/RELR addends stay in target bytes. CREL is an experimental LLVM format.</p>`);
  for (const kind of Object.keys(labels) as ElfRelocationSummaryKind[]) {
    if (!summary[kind].length) continue;
    out.push(`<h4>${escapeHtml(labels[kind])} distribution</h4>`);
    out.push(renderAutoPagedSortableTable(createElfRelocationSummaryModel(summary, kind)));
  }
  if (relocations.issues.length) {
    out.push(`<p>Analysis is incomplete or contains anomalies:</p><ul>` +
      relocations.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("") + `</ul>`);
  }
  out.push(renderElfSectionEnd());
};
