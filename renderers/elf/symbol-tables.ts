import { escapeHtml } from "../../html-utils.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { ElfSymbolTable } from "../../analyzers/elf/symbol-tables.js";
import type { PagedSortableTableModel } from "../../ui/paged-sortable-table-state.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";

// gABI 5: st_info binding/type nibbles, st_other visibility, reserved section indices.
// https://gabi.xinuos.com/elf/05-symtab.html
const symbolValues = (table: ElfSymbolTable, index: number): string[] => {
  const symbol = table.entries[index];
  if (!symbol) return [];
  return [String(index), symbol.name,
    ({ 0: "LOCAL", 1: "GLOBAL", 2: "WEAK", 10: "GNU_UNIQUE" } as Record<number, string>)[
      symbol.info >> 4] ?? String(symbol.info >> 4),
    ["NOTYPE", "OBJECT", "FUNC", "SECTION", "FILE", "COMMON", "TLS"][
      symbol.info & 15] ?? ((symbol.info & 15) === 10 ? "GNU_IFUNC" : String(symbol.info & 15)),
    ["DEFAULT", "INTERNAL", "HIDDEN", "PROTECTED"][symbol.other & 3]!,
    `0x${symbol.value.toString(16)}`, String(symbol.size),
    ({ 0: "UND", 65521: "ABS", 65522: "COMMON" } as Record<number, string>)[
      symbol.sectionIndex] ?? String(symbol.sectionIndex)];
};

export const createElfSymbolTableModel = (table: ElfSymbolTable): PagedSortableTableModel => ({
  id: `elf-symbols-${table.sectionIndex}`, pageSize: 100, rowCount: table.entries.length,
  columns: ["Index", "Name", "Bind", "Type", "Visibility", "Value", "Size", "Section"]
    .map((label, index) => ({ label, className: [0, 5, 6, 7].includes(index) ? "peNumeric" : "" })),
  rowAt: index => table.entries[index] ? {
    cells: symbolValues(table, index).map((value, column) => ({ html: escapeHtml(value),
      sortValue: value, className: [0, 5, 6, 7].includes(column) ? "peNumeric" : "" }))
  } : null,
  sortValueAt: (index, column) => symbolValues(table, index)[column] ?? ""
});

export const renderElfSymbolTables = (elf: ElfParseResult, out: string[]): void => {
  for (const table of elf.symbolTables ?? []) {
    const section = elf.sections.find(item => item.index === table.sectionIndex);
    out.push(renderElfSectionStart(`Symbols: ${section?.name || `section #${table.sectionIndex}`}`));
    out.push(renderAutoPagedSortableTable(createElfSymbolTableModel(table)));
    if (table.issues.length) {
      out.push(`<ul>${table.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`);
    }
    out.push(renderElfSectionEnd());
  }
};
