import type { DModuleInfo } from "../../analyzers/d-runtime/types.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";
import { escapeHtml } from "../../html-utils.js";

export const D_REFERENCE_TABLE_ID = "pe-d-runtime-references";

export const createDRuntimeReferenceTableModel = (
  modules: DModuleInfo[]
): PagedSortableTableModel => {
  const names = new Map(modules.map(module => [module.address, module.name]));
  const rows = modules.flatMap(module => [
    ...module.importedModules.map(address => ({ module: module.name,
      kind: "Imported ModuleInfo", address, name: names.get(address) ?? "" })),
    ...module.localClasses.map(address => ({ module: module.name,
      kind: "Local ClassInfo reference", address, name: "" }))
  ]);
  const values = (index: number): string[] | null => {
    const row = rows[index];
    return row ? [row.module, row.kind, row.name, row.address.toString()] : null;
  };
  const columns = [{ label: "Source module" }, { label: "Reference" },
    { label: "Target module" }, { label: "Target VA", className: "peNumeric" }];
  return {
    id: D_REFERENCE_TABLE_ID, pageSize: 250, rowCount: rows.length,
    columns,
    rowAt: index => {
      const row = rows[index];
      if (!row) return null;
      return { cells: values(index)!.map((sortValue, column) => ({
        html: escapeHtml(column === columns.length - 1 ? `0x${row.address.toString(16)}` : sortValue),
        sortValue,
        ...(columns[column]!.className ? { className: columns[column]!.className } : {})
      })) };
    },
    sortValueAt: (index, column) => values(index)?.[column] ?? ""
  };
};
