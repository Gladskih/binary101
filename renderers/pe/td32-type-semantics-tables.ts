import type { PeTd32Info } from "../../analyzers/pe/debug/td32.js";
import type { Td32Types } from "../../analyzers/pe/debug/td32-type-records.js";
import type { Td32TypeBody } from "../../analyzers/pe/debug/td32-type-body-types.js";
import type { Td32Table } from "./td32-tables.js";

type TypeRecord = Td32Types["records"][number];
type ResolveType = (index: number | undefined) => string;
const hex = (value: number | undefined): string => value === undefined ? "" : `0x${value.toString(16).padStart(4, "0")}`;
const decimal = (value: number | undefined): string => value === undefined ? "" : String(value);

// Type IDs reserve values below 0x1000 for primitives; table indices are zero-based.
// Zero is a null reference. Keep primitive IDs without guessing Delphi type names.
// https://github.com/andremussche/map2dbg/blob/70cd89ff693cd622215309b0acb4326e530e7884/tds2pdb/tds2pdb/Program.cs
const resolveType = (records: ReadonlyMap<number, TypeRecord>, names: readonly string[],
  reference: number | undefined): string => {
  if (reference === undefined) return "";
  if (reference === 0) return "(none)";
  if (reference < 0x1000) return `Primitive ${hex(reference)}`;
  const index = reference - 0x1000;
  const record = records.get(index);
  if (!record) return `(unresolved type #${index})`;
  if (!record.nameIndex) return `#${index}`;
  return `#${index} ${names[record.nameIndex - 1] ?? `(unresolved name #${record.nameIndex})`}`;
};

const qualifierColumns = (record: TypeRecord, resolve: ResolveType): string[] => [
  record.type === 1 ? "Modifier" : "Pointer", hex(record.body!.attributes),
  resolve(record.body!.targetType), hex(record.body!.memberAttributes), resolve(record.body!.classType)
];

const unresolvedSlots = (body: Td32TypeBody): string =>
  ([12, 14, 16, 20] as const).flatMap(offset => {
    const value = body[`relation${offset}`];
    return value === undefined ? [] : [`+${offset}=${hex(value)}`];
  }).join("; ");

const sizeText = (size: Td32TypeBody["byteSize"]): string => {
  if (!size) return "";
  return size.value ?? `Uninterpreted numeric leaf ${hex(size.leaf)}`;
};

const aggregateColumns = (record: TypeRecord, resolve: ResolveType): string[] => [
  record.type === 4 ? "Class" : record.type === 5 ? "Structure" : "Enum",
  decimal(record.body!.count), resolve(record.body!.fieldList), resolve(record.body!.underlyingType),
  hex(record.body!.attributes), sizeText(record.body!.byteSize), unresolvedSlots(record.body!)
];

const procedureColumns = (record: TypeRecord, resolve: ResolveType): string[] => [
  resolve(record.body!.returnType), hex(record.body!.callingConvention),
  hex(record.body!.functionAttributes), decimal(record.body!.parameterCount),
  resolve(record.body!.argumentList), resolve(record.body!.classType), resolve(record.body!.thisType),
  decimal(record.body!.thisAdjustment)
];

const bitFieldColumns = (record: TypeRecord, resolve: ResolveType): string[] => [
  resolve(record.body!.underlyingType), decimal(record.body!.bitLength), decimal(record.body!.bitPosition)
];

const argumentRows = (record: TypeRecord, resolve: ResolveType): string[][] => {
  const argumentsList = record.body!.argumentTypes ?? [];
  return argumentsList.length
    ? argumentsList.map((type, index) => [String(index), resolve(type)]) : [["", "(empty list)"]];
};

const TABLE_KEYS: Readonly<Partial<Record<number, string>>> = {
  1: "typequalifiers", 2: "typequalifiers", 4: "typeaggregates", 5: "typeaggregates",
  7: "typeaggregates", 8: "typeprocedures", 9: "typeprocedures",
  0x201: "typearguments", 0x206: "typebitfields"
};
const COLUMN_BUILDERS: Readonly<Partial<Record<number,
  (record: TypeRecord, resolve: ResolveType) => string[]>>> = {
  1: qualifierColumns, 2: qualifierColumns, 4: aggregateColumns, 5: aggregateColumns,
  7: aggregateColumns, 8: procedureColumns, 9: procedureColumns, 0x206: bitFieldColumns
};

type Subsection = PeTd32Info["directories"][number]["subsections"][number];
const appendTypes = (section: Subsection, names: readonly string[], generation: string,
  tables: ReadonlyMap<string, Td32Table>): void => {
  if (section.data?.kind !== "types") return;
  const records = new Map(section.data.records.map(record => [record.index, record]));
  const resolve: ResolveType = reference => resolveType(records, names, reference);
  for (const record of section.data.records) {
    const table = tables.get(TABLE_KEYS[record.type] ?? "");
    if (!record.body || !table) continue;
    for (const row of record.type === 0x201 ? argumentRows(record, resolve)
      : [COLUMN_BUILDERS[record.type]!(record, resolve)]) {
      table.rows.push([generation, String(section.module), String(record.index), ...row]);
    }
  }
};

export const buildTd32TypeSemanticsTables = (td32: PeTd32Info): Td32Table[] => {
  const base = ["Directory", "Module", "Type index"];
  const tables: Td32Table[] = [
    { key: "typequalifiers", title: "TD32 modifiers and pointers", columns: [...base,
      "Kind", "Attributes", "Target type", "Member attributes", "Class type"], rows: [] },
    { key: "typeaggregates", title: "TD32 classes, structures and enums", columns: [...base,
      "Kind", "Members/values", "Field list", "Underlying type", "Attributes", "Bytes",
      "Raw slots (meaning unresolved)"], rows: [] },
    { key: "typeprocedures", title: "TD32 procedure types", columns: [...base,
      "Return type", "Calling convention", "Function attributes", "Parameters", "Argument list",
      "Class type", "This type", "This adjustment"], rows: [] },
    { key: "typearguments", title: "TD32 argument types", columns: [...base,
      "Position", "Argument type"], rows: [] },
    { key: "typebitfields", title: "TD32 bit fields", columns: [...base,
      "Underlying type", "Bit length", "Bit position"], rows: [] }
  ];
  const byKey = new Map(tables.map(table => [table.key, table]));
  td32.directories.forEach((directory, index) => {
    const names = directory.subsections.find(section => section.data?.kind === "names")?.data;
    for (const section of directory.subsections) appendTypes(section,
      names?.kind === "names" ? names.names : [], String(index + 1), byKey);
  });
  return tables.filter(table => table.rows.length);
};
