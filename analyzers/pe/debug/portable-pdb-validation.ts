import type { ClrParsedTableStream, ClrParsedTable, ClrMetadataRow } from "../clr/metadata-table-reader.js";
import type { ClrHeapReaders } from "../clr/metadata-heaps.js";
import type { PeClrMetadataIndex } from "../clr/types.js";

const validateTableIndex = (
  cell: PeClrMetadataIndex, name: string, parsed: ClrParsedTableStream, heaps: ClrHeapReaders
): void => {
  const listEnd = ["VariableList", "ConstantList"].includes(name) &&
    cell.row > 0 && cell.row === (parsed.tables.get(cell.tableId)?.rows.length ?? 0) + 1;
  if (!cell.valid && !listEnd) heaps.issues.push(`Portable PDB ${name} has an out-of-range table index.`);
};

const validateHeapRow = (
  table: ClrParsedTable, row: ClrMetadataRow, parsed: ClrParsedTableStream, heaps: ClrHeapReaders
): void => {
  for (const column of table.schema.columns) {
    const cell = row[column.name]!;
    const context = `Portable PDB ${table.schema.name}.${column.name}`;
    if (typeof cell !== "number") validateTableIndex(cell, column.name, parsed, heaps);
    else if (column.kind === "string") heaps.getString(cell, context);
    else if (column.kind === "guid") heaps.getGuid(cell, context);
    else if (column.kind === "blob") heaps.getBlob(cell, context);
  }
};

const requireTableIndexes = (row: ClrMetadataRow, names: string[], heaps: ClrHeapReaders): void => {
  for (const name of names) {
    const cell = row[name];
    if (typeof cell !== "number" && cell?.row === 0) {
      heaps.issues.push(`Portable PDB required ${name} index is nil.`);
    }
  }
};

const validateScope = (row: ClrMetadataRow, heaps: ClrHeapReaders): void => {
  requireTableIndexes(row, ["Method", "VariableList", "ConstantList"], heaps);
  if (Number(row["Length"]) === 0) heaps.issues.push("Portable PDB LocalScope is empty.");
  if (Number(row["StartOffset"]) + Number(row["Length"]) >= 0x80000000) {
    heaps.issues.push("Portable PDB LocalScope IL range is out of bounds.");
  }
};

const validateImportParent = (row: ClrMetadataRow, index: number, heaps: ClrHeapReaders): void => {
  const parent = row["Parent"];
  // ImportScope parents precede their children, preventing reference cycles.
  // https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md#importscope-table-0x35
  if (typeof parent !== "number" && parent && parent.row >= index + 1) {
    heaps.issues.push("Portable PDB ImportScope parent does not precede its child.");
  }
};

export const validatePortablePdbRows = (
  parsed: ClrParsedTableStream, heaps: ClrHeapReaders, referencedRows: ReadonlyMap<number, number>
): void => {
  const methods = parsed.tables.get(0x31)?.rows.length ?? 0;
  if (methods && methods !== (referencedRows.get(0x06) ?? 0)) {
    heaps.issues.push("Portable PDB MethodDebugInformation row count differs from MethodDef.");
  }
  for (const [id, table] of parsed.tables) {
    if (id < 0x30 || id > 0x37) continue;
    table.rows.forEach((row, index) => {
      validateHeapRow(table, row, parsed, heaps);
      if (id === 0x32) validateScope(row, heaps);
      if (id === 0x35) validateImportParent(row, index, heaps);
      if (id === 0x36) requireTableIndexes(row, ["MoveNextMethod", "KickoffMethod"], heaps);
      if (id === 0x37) requireTableIndexes(row, ["Parent"], heaps);
    });
  }
};