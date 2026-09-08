import { escapeHtml } from "../../html-utils.js";
import { elfRelocationTypeName } from "../../analyzers/elf/relocation-names.js";
import type { ElfRelocation } from "../../analyzers/elf/relocation-types.js";
import type { ElfParseResult, ElfSectionHeader } from "../../analyzers/elf/types.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import type { PagedSortableTableModel } from "../../ui/paged-sortable-table-state.js";
import { formatElfHex } from "./value-format.js";
import { ELF_FILE_TYPE, ELF_SYMBOL_INDEX } from "../../analyzers/elf/abi-constants.js";

const targetText = (sections: Map<number, ElfSectionHeader>, entry: ElfRelocation): string => {
  const target = entry.target;
  if (!target) return "Unmapped";
  const section = target.sectionIndex == null ? null : sections.get(target.sectionIndex);
  const label = section?.name || (target.sectionIndex == null ? "" : `#${target.sectionIndex}`);
  return label ? `${label} + ${formatElfHex(target.sectionOffset ?? 0n)}` : "PT_LOAD";
};

const columnValues = (elf: ElfParseResult): Array<(entry: ElfRelocation) => string | bigint> => {
  const tables = elf.relocations?.tables ?? [];
  const sources = tables.map(table => table.sources.join(", "));
  const plt = tables.filter(table => table.sources.includes("DT_JMPREL"));
  const sections = new Map(elf.sections.map(section => [section.index, section]));
  return [entry => sources[entry.tableIndex]! +
    (plt.some(table => entry.recordOffset >= table.offset &&
      entry.recordOffset < table.offset + table.size) &&
      !tables[entry.tableIndex]!.sources.includes("DT_JMPREL") ? " (PLT)" : ""),
  entry => tables[entry.tableIndex]!.encoding, entry => entry.offset,
  entry => entry.type == null ? "Relative (RELR)" : elfRelocationTypeName(elf.header.machine, entry.type),
  entry => entry.symbolIndex == null ? "—" : entry.symbolIndex === ELF_SYMBOL_INDEX.UNDEF ? "0 (no symbol)" :
    `#${entry.symbolIndex} ${entry.symbol?.name || "(unnamed/unresolved)"}`,
  entry => entry.addend ?? "Implicit", entry => targetText(sections, entry),
  entry => entry.target?.fileOffset ?? "—"];
};

export const createElfRelocationTableModel = (elf: ElfParseResult): PagedSortableTableModel => {
  const values = columnValues(elf);
  return {
    id: "elf-relocations", pageSize: 100, // UI page size; the parser has a separate resource limit.
    rowCount: elf.relocations?.entries.length ?? 0,
    columns: ["Source", "Format", elf.header.type === ELF_FILE_TYPE.REL ? "Section offset" : "Virtual address",
      "Relocation type", "Symbol", "Addend", "Target", "File offset"]
      .map((label, index) => ({ label, className: [2, 5, 7].includes(index) ? "peNumeric" : "" })),
    rowAt: index => {
      const entry = elf.relocations?.entries[index];
      return entry ? { cells: values.map((read, column) => {
        const value = read(entry);
        return {
          html: escapeHtml(typeof value === "bigint" && column !== 5 ? formatElfHex(value) : value),
          sortValue: String(value), className: [2, 5, 7].includes(column) ? "peNumeric" : ""
        };
      }) } : null;
    },
    sortValueAt: (row, column) => {
      const entry = elf.relocations?.entries[row];
      return entry ? String(values[column]?.(entry) ?? "") : "";
    }
  };
};

export const renderElfRelocations = (elf: ElfParseResult, out: string[]): void => {
  const relocations = elf.relocations;
  if (!relocations) return;
  out.push(`<section><h4>Relocations (${relocations.entries.length})</h4>`);
  out.push(`<p class="smallNote">Targets identify where the loader or linker applies each ` +
    `relocation. REL and RELR addends remain in the target bytes; runtime symbol binding ` +
    `and load addresses are not resolved here.</p>`);
  if (relocations.entries.length) out.push(renderAutoPagedSortableTable(createElfRelocationTableModel(elf)));
  if (relocations.issues.length) {
    out.push(`<ul>${relocations.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`);
  }
  out.push(`</section>`);
};
