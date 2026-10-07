import { escapeHtml } from "../../html-utils.js";
import { dwarfUnitRoot } from "../../analyzers/dwarf/attribute-values.js";
import { dwarfTagLabel } from "../../analyzers/dwarf/tag-names.js";
import { dwarfNameIndexUnit } from "../../analyzers/dwarf/name-index-validation.js";
import type { DwarfNameIndex } from "../../analyzers/dwarf/name-index-types.js";
import type { DwarfAnalysis } from "../../analyzers/dwarf/types.js";
import type { DwarfPublicNames } from "../../analyzers/dwarf/lookup-types.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";

const tableModel = (id: string, rows: string[][]): PagedSortableTableModel => ({
  id, rowCount: rows.length, pageSize: 100,
  columns: [{ label: "Indexed name" }, { label: "Kind" }, { label: "Source unit" }],
  rowAt: index => rows[index] ? { cells: rows[index]!.map(value => ({ html: escapeHtml(value) })) } : null,
  sortValueAt: (index, column) => rows[index]?.[column] ?? ""
});

export const createDwarfPublicNameTableModel = (
  dwarf: DwarfAnalysis, table: DwarfPublicNames
): PagedSortableTableModel => {
  const unit = dwarf.units.find(unit => unit.sectionName === ".debug_info" && BigInt(unit.offset) === table.unitOffset);
  const dies = new Map(unit?.dies.map(die => [BigInt(die.offset - unit.offset), die]));
  const source = dwarfUnitRoot(unit)?.name ?? "unresolved compilation unit";
  return tableModel(`dwarf-public-${table.sectionName}-${table.offset}`, table.entries.map(entry => {
    const die = dies.get(entry.dieOffset);
    return [entry.name, die ? dwarfTagLabel(die.tag).replaceAll("_", " ") : "unresolved DIE", source];
  }));
};

export const createDwarfNameIndexTableModel = (dwarf: DwarfAnalysis, table: DwarfNameIndex): PagedSortableTableModel =>
  tableModel(`dwarf-names-${table.offset}`, table.names.flatMap(name => name.entries.map(entry => {
    const unit = dwarfNameIndexUnit(table, entry, dwarf.units);
    return [name.name.kind === "string" ? name.name.value : "unresolved indexed name",
      dwarfTagLabel(entry.tag).replaceAll("_", " "), dwarfUnitRoot(unit)?.name ?? "unresolved unit"];
  })));

const renderAddressLookup = (dwarf: DwarfAnalysis): string => {
  const tables = dwarf.addressLookup ?? [];
  if (!tables.length) return "";
  return `<h5>Compilation-unit coverage</h5><div class="tableWrap"><table class="table">` +
    `<thead><tr><th>Source unit</th><th>Ranges</th><th>Covered bytes</th></tr></thead><tbody>` +
    tables.map(table => {
      const unit = dwarf.units.find(unit => unit.sectionName === ".debug_info" && BigInt(unit.offset) === table.unitOffset);
      return `<tr><td>${escapeHtml(dwarfUnitRoot(unit)?.name ?? "unresolved compilation unit")}</td>` +
        `<td class="dwarfTable__numeric">${table.ranges.length}</td>` +
        `<td class="dwarfTable__numeric">${table.ranges.reduce((size, range) => size + range.length, 0n)}</td></tr>`;
    }).join("") + "</tbody></table></div>";
};

export const renderDwarfLookups = (dwarf: DwarfAnalysis): string =>
  (dwarf.publicNames ?? []).filter(table => table.entries.length).map(table =>
    `<details><summary>${escapeHtml(table.sectionName.includes("types") ? "Indexed public types" : "Indexed public names")}` +
    ` (${table.entries.length})</summary>` + renderAutoPagedSortableTable(createDwarfPublicNameTableModel(dwarf, table)) +
    "</details>"
  ).join("") + (dwarf.nameIndexes ?? []).filter(table => table.names.some(name => name.entries.length)).map(table =>
    `<details><summary>Debugger name index (${table.names.length} names)</summary>` +
    renderAutoPagedSortableTable(createDwarfNameIndexTableModel(dwarf, table)) + "</details>"
  ).join("") + renderAddressLookup(dwarf);

export const getDwarfLookupTableModel = (dwarf: DwarfAnalysis, id: string): PagedSortableTableModel | null => {
  const publicNames = dwarf.publicNames?.find(table => id === `dwarf-public-${table.sectionName}-${table.offset}`);
  if (publicNames) return createDwarfPublicNameTableModel(dwarf, publicNames);
  const names = dwarf.nameIndexes?.find(table => id === `dwarf-names-${table.offset}`);
  return names ? createDwarfNameIndexTableModel(dwarf, names) : null;
};
