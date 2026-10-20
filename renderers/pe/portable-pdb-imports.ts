import type { PortablePdbInfo } from "../../analyzers/pe/debug/portable-pdb-types.js";
import type { PortablePdbImport } from "../../analyzers/pe/debug/portable-pdb-imports.js";
import { PortablePdbTypeNames } from "../../analyzers/pe/debug/portable-pdb-type-names.js";
import type { PeClrMetadataTables } from "../../analyzers/pe/clr/types.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { escapeHtml } from "../../html-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";

// https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md#imports-blob
const IMPORT_NAMES: Readonly<Record<number, string>> = {
  1: "Namespace", 2: "Assembly namespace", 3: "Type", 4: "XML namespace", 5: "Assembly alias",
  6: "Assembly alias definition", 7: "Namespace alias", 8: "Assembly namespace alias", 9: "Type alias"
};

const assemblyName = (row: number | undefined, metadata: PeClrMetadataTables | undefined): string | null =>
  row === undefined ? null : metadata?.assemblyRefs[row - 1]?.name ?? `AssemblyRef #${row}`;

const importTarget = (value: PortablePdbImport, names: PortablePdbTypeNames, assembly: string | null): string => {
  if (Object.hasOwn(value, "targetNamespace")) {
    const name = value.targetNamespace ?? "(unreadable namespace)";
    return `${name || "(global namespace)"}${assembly ? ` (${assembly})` : ""}`;
  }
  if (value.targetType) return names.get(value.targetType) ??
    `${({ 1: "TypeRef", 2: "TypeDef", 27: "TypeSpec" } as Record<number, string>)[value.targetType.tableId] ?? "Type"} #${value.targetType.row}`;
  return assembly ?? "Alias from parent scope";
};

const createImportModel = (
  pdb: PortablePdbInfo, id: string, metadata: PeClrMetadataTables | undefined
): PagedSortableTableModel => {
  const names = new PortablePdbTypeNames(metadata);
  const rows = pdb.imports.flatMap((scope, index) => scope.imports.map(value => ({
    value, scope: index + 1, parent: scope.parent
  })));
  const cells = (row: (typeof rows)[number]): string[] => [
    IMPORT_NAMES[row.value.kind] ?? "Unknown import", importTarget(row.value, names, assemblyName(row.value.targetAssembly, metadata)),
    row.value.alias === undefined ? "(none)" : row.value.alias ?? "(unreadable alias)",
    `${row.scope}${row.parent ? ` (parent ${row.parent})` : " (root)"}`
  ];
  return {
    id, pageSize: 100, rowCount: rows.length,
    columns: ["Import kind", "Target", "Alias", "Scope"].map(label => ({ label })),
    rowAt: index => rows[index] ? { cells: cells(rows[index]!).map(value => ({ html: escapeHtml(value) })) } : null,
    sortValueAt: (index, column) => rows[index] ? cells(rows[index]!)[column] ?? "" : ""
  };
};

export const getPortablePdbImportTableModel = (
  pe: PeWindowsParseResult, tableId: string
): PagedSortableTableModel | null => {
  const match = /^pe-debug-entry-(\d+)-imports$/.exec(tableId);
  if (!match) return null;
  const pdb = pe.debug?.entries?.[Number(match[1])]?.embeddedPortablePdb?.portablePdb;
  return pdb ? createImportModel(pdb, tableId, pe.clr?.meta?.tables) : null;
};

export const renderPortablePdbImports = (
  pdb: PortablePdbInfo, out: string[], entryIndex: number, metadata?: PeClrMetadataTables
): void => {
  const model = createImportModel(pdb, `pe-debug-entry-${entryIndex}-imports`, metadata);
  if (model.rowCount) out.push(renderAutoPagedSortableTable(model));
};
