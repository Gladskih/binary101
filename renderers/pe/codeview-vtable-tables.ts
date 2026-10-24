import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import type { LegacyCodeViewTypeRecord, LegacyCodeViewTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { indexCodeViewTypes, createCodeViewTypeFormatter } from "./codeview-type-names.js";

const tableName = (record: LegacyCodeViewTypeRecord): string => {
  const name = record.strings?.[0];
  return name === undefined ? "(table name unavailable)" : name || "(unnamed table)";
};

const baseTable = (index: number, indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>): string => {
  if (index === 0) return "(none)";
  const record = indexed.get(index);
  if (!record) return `${record === null ? "ambiguous" : "missing"} virtual table #${index}`;
  return record.shape?.kind === "vtable" ? tableName(record) : `type #${index} is not a virtual table`;
};

const vtableRows = (record: LegacyCodeViewTypeRecord,
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>, describe: (index: number) => string): string[][] => {
  const shape = record.shape;
  if (shape?.kind !== "vtable") return [];
  return [[tableName(record), describe(shape.ownerType), String(shape.pointerOffset),
    baseTable(shape.baseTable, indexed),
    record.strings === undefined ? "unavailable" : String(Math.max(0, record.strings.length - 1))]];
};

const pathRows = (record: LegacyCodeViewTypeRecord, describe: (index: number) => string): string[][] => {
  const shape = record.shape;
  return shape?.kind === "vtablePath" ? [[String(record.index ?? "unresolved"),
    shape.indices.map(describe).join(" → ") || "(empty)"]] : [];
};

const layoutRows = (data: LegacyCodeViewTypes): Map<string, string[][]> => {
  const indexed = indexCodeViewTypes(data.records);
  const format = createCodeViewTypeFormatter(indexed);
  const external = new Map<number, LegacyCodeViewTypeRecord>();
  const externalFormat = createCodeViewTypeFormatter(external);
  const rows = new Map<string, string[][]>([["virtualTables", []], ["vtablePaths", []]]);
  for (const record of data.records) {
    const local = record.index !== undefined && indexed.get(record.index) === record;
    const describe = local ? format : externalFormat;
    rows.get("virtualTables")!.push(...vtableRows(record, local ? indexed : external, describe));
    rows.get("vtablePaths")!.push(...pathRows(record, describe));
  }
  return rows;
};

export const buildCodeViewVtableTables = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const tables: LegacyCodeViewTable[] = [
    { key: "virtualTables", title: "Virtual table layouts", columns: ["Directory", "Module", "Table name",
      "Owner type", "Pointer offset", "Base table", "Stored method names"], rows: [] },
    { key: "vtablePaths", title: "Paths to virtual tables",
      columns: ["Directory", "Module", "Path type index", "Base classes (root to leaf)"], rows: [] }
  ];
  info.directories.forEach((directory, index) => {
    for (const section of directory.subsections) {
      if (section.data?.kind !== "types" || section.data.encoding) continue;
      const rows = layoutRows(section.data);
      for (const table of tables) for (const row of rows.get(table.key)!) {
        table.rows.push([String(index + 1), String(section.module), ...row]);
      }
    }
  });
  return tables.filter(table => table.rows.length);
};
