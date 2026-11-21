import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { ElfSymbolTable } from "../../analyzers/elf/symbol-tables.js";
import { escapeHtml } from "../../html-utils.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import { createElfSymbolTableModel } from "./symbol-tables.js";

const miniDebugTableId = (table: ElfSymbolTable): string =>
  `elf-mini-debug-symbols-${table.sectionIndex}`;

export const getElfMiniDebugTable = (elf: ElfParseResult, id: string) => {
  const mini = elf.miniDebugInfo;
  const table = mini?.symbolTables.find(candidate => miniDebugTableId(candidate) === id);
  return mini && table ? createElfSymbolTableModel(table, mini.sections, elf.header.machine, id) : null;
};

export const renderElfMiniDebugInfo = (elf: ElfParseResult): string => {
  const mini = elf.miniDebugInfo;
  if (!mini) return "";
  const tables = mini.symbolTables.map(table =>
    `<h5>Embedded symbol table #${table.sectionIndex}</h5>` +
    renderAutoPagedSortableTable(createElfSymbolTableModel(table, mini.sections,
      elf.header.machine, miniDebugTableId(table)))).join("");
  const issues = [...mini.issues, ...mini.symbolTables.flatMap(table => table.issues)];
  const warnings = issues.length ? `<ul>${issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul>` : "";
  return "<h4>MiniDebugInfo (.gnu_debugdata)</h4>" +
    '<p class="smallNote">The compressed ELF carries additional symbols, commonly for backtraces. ' +
    "Section numbers below belong to the embedded ELF.</p>" +
    (tables || "<p>No embedded symbol tables decoded.</p>") + warnings;
};
