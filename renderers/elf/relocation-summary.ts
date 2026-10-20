import type { ElfParseResult, ElfSectionHeader } from "../../analyzers/elf/types.js";
import type { ElfRelocation, ElfRelocationSymbol, ElfRelocationTable } from "../../analyzers/elf/relocation-types.js";
import { elfRelocationTypeName } from "../../analyzers/elf/relocation-names.js";

export interface ElfRelocationSummaryRow {
  label: string; detail: string; count: number; symbol?: ElfRelocationSymbol;
}
export type ElfRelocationSummaryKind = "types" | "formats" | "targets" | "symbols";
export type ElfRelocationSummary = Record<ElfRelocationSummaryKind, ElfRelocationSummaryRow[]>;

const addRow = (rows: Map<string, ElfRelocationSummaryRow>, key: string,
  label: string, detail: string, symbol?: ElfRelocationSymbol): void => {
  const existing = rows.get(key);
  if (existing) existing.count++;
  else rows.set(key, { label, detail, count: 1, ...(symbol ? { symbol } : {}) });
};

const symbolState = (entry: ElfRelocation): string => {
  if (!entry.symbol) return "Unresolved symbol reference";
  // gABI SHN_UNDEF/ABS/COMMON: a definition need not belong to a section.
  if (entry.symbol.sectionIndex === 0) return "Undefined; requires symbol lookup";
  if (entry.symbol.sectionIndex === 0xfff1) return "Absolute definition";
  if (entry.symbol.sectionIndex === 0xfff2) return "Common definition";
  return "Defined in this file";
};

const targetLabel = (sections: Map<number, ElfSectionHeader>, entry: ElfRelocation): string => {
  if (!entry.target) return entry.type === 0 ? "No target (NONE)" : "Unmapped";
  if (entry.target.sectionIndex == null) return "PT_LOAD (section unavailable)";
  return sections.get(entry.target.sectionIndex)?.name || `Section #${entry.target.sectionIndex}`;
};

const targetStorage = (entry: ElfRelocation): string => entry.target ?
  entry.target.fileOffset == null ? "No file bytes" : "File-backed" : "";

const symbolLabel = (sections: Map<number, ElfSectionHeader>, entry: ElfRelocation): string => {
  if (!entry.symbol) return "Unresolved symbol";
  return entry.symbol.name || sections.get(entry.symbol.sectionIndex)?.name || "Unnamed symbol";
};

const symbolTableIdentity = (sections: Map<number, ElfSectionHeader>, table: ElfRelocationTable): string | number => {
  if (table.symbolTableIndex == null) return "dynamic";
  return sections.get(table.symbolTableIndex)?.type === 11 ? "dynamic" : table.symbolTableIndex;
};

const typeLabel = (machine: number, table: ElfRelocationTable, entry: ElfRelocation): string =>
  entry.type == null ? table.encoding === "AUTH_RELR" ? "Authenticated relative (RELR)" :
    "Relative (RELR)" : elfRelocationTypeName(machine, entry.type);

export const summarizeElfRelocations = (elf: ElfParseResult): ElfRelocationSummary => {
  const types = new Map<string, ElfRelocationSummaryRow>();
  const formats = new Map<string, ElfRelocationSummaryRow>();
  const targets = new Map<string, ElfRelocationSummaryRow>();
  const symbols = new Map<string, ElfRelocationSummaryRow>();
  const sections = new Map(elf.sections.map(section => [section.index, section]));
  for (const entry of elf.relocations?.entries ?? []) {
    const table = elf.relocations!.tables[entry.tableIndex]!;
    const type = typeLabel(elf.header.machine, table, entry);
    const binding = entry.symbolIndex ? "Symbol reference" : "No symbol reference";
    addRow(types, `${type}:${binding}`, type, binding);
    const addend = entry.addend == null ? "Addend in target bytes" : "Explicit addend";
    addRow(formats, `${table.encoding}:${addend}`, table.encoding, addend);
    const target = targetLabel(sections, entry);
    const storage = targetStorage(entry);
    addRow(targets, `${entry.target?.sectionIndex}:${target}:${storage}`, target, storage);
    if (!entry.symbolIndex) continue;
    addRow(symbols, `${symbolTableIdentity(sections, table)}:${entry.symbolIndex}`,
      symbolLabel(sections, entry), symbolState(entry), entry.symbol ?? undefined);
  }
  const sorted = (rows: Map<string, ElfRelocationSummaryRow>): ElfRelocationSummaryRow[] =>
    [...rows.values()].sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
  return { types: sorted(types), formats: sorted(formats), targets: sorted(targets), symbols: sorted(symbols) };
};
