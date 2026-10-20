import type { PeFixupInfo } from "../../analyzers/pe/debug/fixup.js";
import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { formatCoffRelocationType } from "../../analyzers/coff/relocation-types.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { createDebugSectionNameLookup } from "./debug-section-names.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";

interface FixupUsage {
  types: [number, number][];
  sections: [string, string, number][];
  sources: number;
  targets: number;
  extraRecords: number;
}

const summarizeFixups = (pe: PeWindowsParseResult, fixup: PeFixupInfo): FixupUsage => {
  const sectionName = createDebugSectionNameLookup(pe.sections);
  const types = new Map<number, number>();
  const sections = new Map<string, Map<string, number>>();
  const sources = new Set<number>();
  const targets = new Set<number>();
  let extraRecords = 0;
  for (const record of fixup.records) {
    types.set(record.type, (types.get(record.type) ?? 0) + 1);
    sources.add(record.rva);
    targets.add(record.targetRva);
    if (record.extra) extraRecords++;
    const source = sectionName(record.rva);
    const target = sectionName(record.targetRva);
    const links = sections.get(source) ?? new Map<string, number>();
    links.set(target, (links.get(target) ?? 0) + 1);
    sections.set(source, links);
  }
  return { sources: sources.size, targets: targets.size, extraRecords,
    types: [...types].sort((left, right) => right[1] - left[1]),
    sections: [...sections].flatMap(([source, links]) => [...links].map(
      ([target, count]): [string, string, number] => [source, target, count]))
      .sort((left, right) => right[2] - left[2]) };
};

const typeTable = (usage: FixupUsage, machine: number, id: string): PagedSortableTableModel => ({
  id, pageSize: 100, rowCount: usage.types.length,
  columns: [{ label: "Fixup kind" }, { label: "Records", className: "peNumeric" }],
  rowAt: index => {
    const row = usage.types[index];
    return row ? { cells: [{ html: escapeHtml(formatCoffRelocationType(machine, row[0])) },
      { html: String(row[1]), className: "peNumeric" }] } : null;
  },
  sortValueAt: (index, column) => {
    const row = usage.types[index];
    return row ? [formatCoffRelocationType(machine, row[0]), String(row[1])][column] ?? "" : "";
  }
});

const sectionTable = (usage: FixupUsage, id: string): PagedSortableTableModel => ({
  id, pageSize: 100, rowCount: usage.sections.length,
  columns: [{ label: "Source section" }, { label: "Target section" }, { label: "Fixups", className: "peNumeric" }],
  rowAt: index => {
    const row = usage.sections[index];
    return row ? { cells: [{ html: escapeHtml(row[0]) }, { html: escapeHtml(row[1]) },
      { html: String(row[2]), className: "peNumeric" }] } : null;
  },
  sortValueAt: (index, column) => {
    const row = usage.sections[index];
    return row ? [row[0], row[1], String(row[2])][column] ?? "" : "";
  }
});

export const getFixupTableModel = (pe: PeWindowsParseResult, tableId: string): PagedSortableTableModel | null => {
  const match = /^pe-debug-entry-(\d+)-fixup-(types|sections)$/.exec(tableId);
  if (!match) return null;
  const fixup = pe.debug?.entries?.[Number(match[1])]?.fixup;
  if (!fixup) return null;
  const usage = summarizeFixups(pe, fixup);
  return match[2] === "types" ? typeTable(usage, pe.coff.Machine, tableId) : sectionTable(usage, tableId);
};

export const renderFixupStatistics = (
  pe: PeWindowsParseResult, entry: PeDebugDirectoryEntry, index: number, out: string[]
): void => {
  if (!entry.fixup) return;
  const usage = summarizeFixups(pe, entry.fixup);
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Fixup records", String(entry.fixup.records.length)));
  out.push(renderDefinitionRow("Distinct source locations", String(usage.sources)));
  out.push(renderDefinitionRow("Distinct target locations", String(usage.targets)));
  out.push(renderDefinitionRow("Records with extra linker metadata", String(usage.extraRecords)));
  out.push(`</dl>`);
  if (usage.types.length) out.push(renderAutoPagedSortableTable(
    typeTable(usage, pe.coff.Machine, `pe-debug-entry-${index}-fixup-types`)));
  if (usage.sections.length) out.push(renderAutoPagedSortableTable(
    sectionTable(usage, `pe-debug-entry-${index}-fixup-sections`)));
};
