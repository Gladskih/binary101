import { escapeHtml } from "../../html-utils.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { ArmEhabiTable } from "../../analyzers/elf/arm-ehabi-types.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";

const hex = (value: number | bigint | undefined | null): string =>
  value == null ? "Unavailable" : `0x${value.toString(16)}`;

export const createElfArmEhabiModel = (table: ArmEhabiTable, index: number): PagedSortableTableModel => {
  const rows = table.entries.map(entry => [String(entry.offset), hex(entry.functionAddress), hex(entry.tableAddress),
    entry.personality == null ? "" : String(entry.personality),
    entry.instructions.map(instruction => `${instruction.offset}: ${instruction.text}`).join("; "),
    entry.issues.join("; ")]);
  return { id: `elf-arm-ehabi-${index}`, pageSize: 100, rowCount: rows.length,
    columns: ["File offset", "Function", "Extab address", "Personality", "Unwind instructions", "Notices"]
      .map((label, column) => ({ label, ...(column < 4 ? { className: "peNumeric" } : {}) })),
    rowAt: row => rows[row] ? { cells: rows[row]!.map(value =>
      ({ html: escapeHtml(String(value)), sortValue: value })) } : null,
    sortValueAt: (row, column) => rows[row]?.[column] ?? ""
  };
};

export const createElfArmScopeModel = (table: ArmEhabiTable, index: number): PagedSortableTableModel => {
  const rows = table.entries.flatMap(entry => (entry.descriptors ?? []).map(scope =>
    [hex(entry.functionAddress), scope.kind, String(scope.start), String(scope.length), hex(scope.landingPad),
      scope.types.map(hex).join(", "), scope.referenceCatch ? "Reference" : ""]));
  return { id: `elf-arm-scopes-${index}`, pageSize: 100, rowCount: rows.length,
    columns: ["Function", "Kind", "Start offset", "Length", "Landing pad", "Type words (TARGET2)", "Catch"]
      .map(label => ({ label })),
    rowAt: row => rows[row] ? { cells: rows[row]!.map(value =>
      ({ html: escapeHtml(value), sortValue: value })) } : null,
    sortValueAt: (row, column) => rows[row]?.[column] ?? ""
  };
};

export const renderElfArmEhabi = (elf: ElfParseResult, out: string[]): void => {
  for (const [index, table] of (elf.armEhabi ?? []).entries()) {
    out.push(renderElfSectionStart(`ARM exception handling (${table.source})`));
    out.push(renderAutoPagedSortableTable(createElfArmEhabiModel(table, index)));
    const scopes = createElfArmScopeModel(table, index);
    if (scopes.rowCount) out.push(renderAutoPagedSortableTable(scopes));
    if (table.issues.length) out.push(`<ul>${table.issues.map(issue =>
      `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`);
    out.push(renderElfSectionEnd());
  }
};
