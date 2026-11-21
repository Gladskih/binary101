import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { ElfRelocation, ElfRelocationInfo, ElfRelocationTable } from "../../analyzers/elf/relocation-types.js";
import { escapeHtml } from "../../html-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { renderCollectionStart, renderCollectionEnd } from "../counted-collection.js";
import { elfRelocationTypeLabel } from "./relocation-summary.js";

const recordsId = "elf-relocation-records";
const display = (value: number | bigint | null): string => value == null ? "—" : `0x${value.toString(16)}`;
const numberCell = (value: number | bigint | null, html = display(value)) => ({
  html,
  sortValue: value?.toString() ?? "", className: "peNumeric"
});
const cell = (value: string) => ({ html: escapeHtml(value), sortValue: value });

const recordCells = (entry: ElfRelocation, table: ElfRelocationTable, machine: number,
  sections: ReadonlyMap<number, string>) => {
  const section = entry.target?.sectionIndex;
  const target = section != null ? sections.get(section) || `Section #${section}` :
    entry.target ? "PT_LOAD" : "—";
  const location = table.compressed ? `Decoded +${display(entry.recordOffset)}` : display(entry.recordOffset);
  return [numberCell(entry.tableIndex, String(entry.tableIndex)), numberCell(entry.recordOffset, location),
    cell(elfRelocationTypeLabel(machine, table, entry)), numberCell(entry.offset),
    numberCell(entry.symbolIndex, String(entry.symbolIndex ?? "—")), cell(entry.symbol?.name || "—"),
    numberCell(entry.addend, String(entry.addend ?? "—")), cell(target),
    numberCell(entry.target?.sectionOffset ?? null), numberCell(entry.target?.fileOffset ?? null)];
};

export const getElfRelocationRecordsModel = (elf: ElfParseResult, id: string): PagedSortableTableModel | null => {
  const relocations = elf.relocations;
  if (id !== recordsId || !relocations) return null;
  const names = new Map(elf.sections.map(section => [section.index, section.name ?? ""]));
  const rowAt = (index: number) => {
    const entry = relocations.entries[index];
    const table = entry && relocations.tables[entry.tableIndex];
    return entry && table ? { cells: recordCells(entry, table, elf.header.machine, names) } : null;
  };
  return { id, pageSize: 100, rowCount: relocations.entries.length,
    columns: ["Table #", "Record location", "Type", "r_offset", "Symbol index", "Symbol",
      "Explicit addend", "Target", "Target section offset", "Target file offset"]
      .map((label, index) => ({ label, className: [0, 1, 3, 4, 6, 8, 9].includes(index) ? "peNumeric" : "" })),
    rowAt, sortValueAt: (index, column) => rowAt(index)?.cells[column]?.sortValue ?? ""
  };
};

const renderTables = (relocations: ElfRelocationInfo): string => {
  const rows = relocations.tables.map((table, index) => {
    const relrWords = (table.encoding === "RELR" || table.encoding === "AUTH_RELR") &&
      !table.compressed && table.entrySize > 0 ? String(Math.floor(table.size / table.entrySize)) : "—";
    return `<tr><td class="peNumeric">${index}</td><td>${escapeHtml(table.sources.join(", "))}</td>` +
      `<td>${table.encoding}</td><td class="peNumeric">${display(table.offset)}</td>` +
      `<td class="peNumeric">${table.size}</td><td class="peNumeric">${relrWords}</td>` +
      `<td>${table.complete === false ? "Partial" : table.complete === true ? "Complete" : "—"}</td></tr>`;
  }).join("");
  return '<div class="tableWrap"><table class="table"><thead><tr><th>Table #</th><th>Sources</th>' +
    '<th>Encoding</th><th>File offset</th><th>Bytes</th><th>Encoded RELR words</th><th>Decode status</th>' +
    `</tr></thead><tbody>${rows}</tbody></table></div>`;
};

export const renderElfRelocationRecords = (elf: ElfParseResult): string => {
  const model = getElfRelocationRecordsModel(elf, recordsId);
  if (!model?.rowCount) return "";
  return renderCollectionStart(`Relocation records (${model.rowCount})`, model.rowCount) +
    '<p class="smallNote">In relocatable objects, r_offset is relative to the target section. ' +
    'In executables and shared objects it is a link-time virtual address. Record location is a file offset, ' +
    'or an offset in decoded bytes for a compressed section. Packed formats can produce several rows ' +
    'from one record location.</p>' +
    renderTables(elf.relocations!) + renderAutoPagedSortableTable(model) +
    renderCollectionEnd(model.rowCount);
};
