import { escapeHtml } from "../../html-utils.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { ElfHashTable } from "../../analyzers/elf/hash-types.js";
import type { PagedSortableTableModel } from "../../ui/paged-sortable-table-state.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";

const hashRow = (table: ElfHashTable, index: number): string[] => {
  if (index < table.buckets.length) return ["Bucket", String(index), String(table.buckets[index])];
  const chain = index - table.buckets.length;
  if (chain < table.chains.length) return ["Chain", String(chain), table.kind === "sysv"
    ? String(table.chains[chain]) : `0x${table.chains[chain]!.toString(16)}${table.chains[chain]! & 1 ? " (end)" : ""}`];
  const bloom = chain - table.chains.length;
  return table.kind === "gnu" && table.bloom[bloom] != null
    ? ["Bloom word", String(bloom), `0x${table.bloom[bloom]!.toString(16)}`] : [];
};

export const createElfHashTableModel = (table: ElfHashTable): PagedSortableTableModel => ({
  id: `elf-hash-${table.kind}-${table.offset}`, pageSize: 100,
  rowCount: table.buckets.length + table.chains.length + (table.kind === "gnu" ? table.bloom.length : 0),
  columns: ["Array", "Index", "Value"].map(label => ({ label, className: "peNumeric" })),
  rowAt: index => {
    const cells = hashRow(table, index);
    return cells.length ? { cells: cells.map(value => ({ html: escapeHtml(value), sortValue: value })) } : null;
  },
  sortValueAt: (index, column) => hashRow(table, index)[column] ?? ""
});

export const renderElfHashTables = (elf: ElfParseResult, out: string[]): void => {
  for (const table of elf.hashTables ?? []) {
    out.push(renderElfSectionStart(`${table.kind === "gnu" ? "GNU" : "System V"} symbol hash table`));
    out.push(`<p>${table.buckets.length} buckets; ${table.chains.length} chain words.</p>`);
    if (table.kind === "gnu") out.push(`<p>First hashed symbol: ${table.symbolOffset}; ` +
      `Bloom shift: ${table.bloomShift}; Bloom words: ${table.bloom.length}.</p>`);
    out.push(renderAutoPagedSortableTable(createElfHashTableModel(table)));
    if (table.issues.length) out.push(`<ul>${table.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`);
    out.push(renderElfSectionEnd());
  }
};
