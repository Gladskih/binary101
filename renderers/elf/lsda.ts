import { escapeHtml } from "../../html-utils.js";
import type { ElfLsda } from "../../analyzers/elf/lsda-types.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";

const lsdaTables = {
  sites: { columns: ["Start offset", "Length", "Landing pad offset", "Action"],
    rows: (lsda: ElfLsda): string[][] => lsda.callSites.map(site =>
      [site.start, site.length, site.landingPad, site.action].map(String)) },
  actions: { columns: ["Record offset", "Type filter", "Next displacement"],
    rows: (lsda: ElfLsda): string[][] => lsda.actions.map(action =>
      [action.offset, action.typeFilter, action.nextOffset].map(String)) },
  types: { columns: ["Type index", "Type pointer"],
    rows: (lsda: ElfLsda): string[][] => lsda.types.map(type => [String(type.index), type.pointer
      ? `${type.pointer.indirect ? "Indirect at " : ""}0x${type.pointer.address.toString(16)}` : "Unavailable"]) },
  specifications: { columns: ["Filter", "Allowed type indices"],
    rows: (lsda: ElfLsda): string[][] => lsda.specifications.map(spec =>
      [String(spec.filter), spec.typeIndices.join(", ")]) }
};
type LsdaTable = keyof typeof lsdaTables;

export const createElfLsdaTableModel = (lsda: ElfLsda, kind: LsdaTable): PagedSortableTableModel => {
  const descriptor = lsdaTables[kind];
  const rows = descriptor.rows(lsda);
  return { id: `elf-lsda-${lsda.address}-${kind}`, pageSize: 100, rowCount: rows.length,
    columns: descriptor.columns.map(label => ({ label, className: "peNumeric" })),
    rowAt: index => rows[index] ? { cells: rows[index]!.map(value =>
      ({ html: escapeHtml(value), sortValue: value, className: "peNumeric" })) } : null,
    sortValueAt: (index, column) => rows[index]?.[column] ?? ""
  };
};

export const getElfLsdaTableModel = (elf: ElfParseResult, id: string): PagedSortableTableModel | null => {
  for (const lsda of elf.lsdas ?? []) {
    for (const kind of Object.keys(lsdaTables) as LsdaTable[]) {
      if (id === `elf-lsda-${lsda.address}-${kind}`) return createElfLsdaTableModel(lsda, kind);
    }
  }
  return null;
};

export const renderElfLsda = (elf: ElfParseResult, out: string[]): void => {
  for (const lsda of elf.lsdas ?? []) {
    out.push(renderElfSectionStart(`LSDA at 0x${lsda.address.toString(16)}`));
    out.push(`<p>GCC/LLVM exception tables. Call-site starts are function-relative; landing pads are base-relative. ` +
      `Action references are one-based byte offsets. Indirect type pointers identify storage.</p>`);
    if (lsda.landingPadBase) out.push(`<p>Landing pad base: 0x${lsda.landingPadBase.address.toString(16)}</p>`);
    for (const kind of Object.keys(lsdaTables) as LsdaTable[]) {
      const model = createElfLsdaTableModel(lsda, kind);
      if (model.rowCount) out.push(renderAutoPagedSortableTable(model));
    }
    if (lsda.issues.length) out.push(`<ul>${lsda.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`);
    out.push(renderElfSectionEnd());
  }
};
