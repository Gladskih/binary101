import { escapeHtml } from "../../html-utils.js";
import type { ElfCoreNote } from "../../analyzers/elf/core-note-types.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";

const coreRows = (core: ElfCoreNote): (string | bigint)[][] => [
  ...core.fields.map(field => [field.name, field.value]),
  ...(core.registers ?? []).map(field => [field.name, `0x${BigInt(field.value).toString(16)}`]),
  ...(core.auxv ?? []).map(pair => [`Auxiliary tag ${pair.tag}`, `0x${pair.value.toString(16)}`])
];

export const createElfCoreTableModel = (core: ElfCoreNote, index: number): PagedSortableTableModel => {
  const rows = coreRows(core);
  return {
    id: `elf-core-${index}`, pageSize: 100, rowCount: rows.length,
    columns: [{ label: "Field / register" }, { label: "Value", className: "peNumeric" }],
    rowAt: row => rows[row] ? { cells: rows[row]!.map(value =>
      ({ html: escapeHtml(String(value)), sortValue: String(value) })) } : null,
    sortValueAt: (row, column) => String(rows[row]?.[column] ?? "")
  };
};

export const createElfCoreMappingModel = (core: ElfCoreNote, index: number): PagedSortableTableModel => {
  const rows = (core.mappings ?? []).map(mapping => [
    `0x${mapping.start.toString(16)}`, `0x${mapping.end.toString(16)}`, mapping.pageOffset, mapping.path
  ]);
  return {
    id: `elf-core-mappings-${index}`, pageSize: 100, rowCount: rows.length,
    columns: ["Start", "End", "File offset (pages)", "File"].map((label, column) =>
      ({ label, className: column < 3 ? "peNumeric" : "" })),
    rowAt: row => rows[row] ? { cells: rows[row]!.map((value, column) =>
      ({ html: escapeHtml(String(value)), sortValue: String(value),
        className: column < 3 ? "peNumeric" : "" })) } : null,
    sortValueAt: (row, column) => String(rows[row]?.[column] ?? "")
  };
};

export const renderElfCoreNotes = (elf: ElfParseResult, out: string[]): void => {
  for (const [index, note] of (elf.notes?.entries ?? []).entries()) {
    if (!note.core) continue;
    out.push(`<h4>${escapeHtml(note.typeName ?? `Core note 0x${note.type.toString(16)}`)} #${index}</h4>`);
    out.push(renderAutoPagedSortableTable(createElfCoreTableModel(note.core, index)));
    if (note.core.mappings) out.push(renderAutoPagedSortableTable(createElfCoreMappingModel(note.core, index)));
    if (note.core.issues.length) out.push(`<ul>${note.core.issues.map(issue =>
      `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`);
  }
};
