import type { PeTd32Info } from "../../analyzers/pe/debug/td32.js";
import type { Td32Types } from "../../analyzers/pe/debug/td32-type-records.js";
import type { Td32TypeBody } from "../../analyzers/pe/debug/td32-type-body-types.js";
import type { Td32Table } from "./td32-tables.js";
import { buildTd32MemberTables } from "./td32-type-member-tables.js";

type TypeRecord = Td32Types["records"][number];
type FlagNames = readonly (readonly [number, string])[];
type Statistic = readonly [measure: string, value: string, count: number];

// Borland enums, not modern CodeView property/calling-convention interpretations:
// ModifierAttributes, PointerType/Mode/Attributes, TdsStructFlags and TdsCallConv.
// https://github.com/andremussche/map2dbg/blob/70cd89ff693cd622215309b0acb4326e530e7884/tds2pdb/tds2pdb/Program.cs
const MODIFIER_FLAGS: FlagNames = [[1, "Const"], [2, "Volatile"], [4, "Unaligned"]];
const POINTER_FLAGS: FlagNames = [[0x100, "Flat 32-bit"], [0x200, "Const"],
  [0x400, "Volatile"], [0x800, "Unaligned"]];
const STRUCTURE_FLAGS: FlagNames = [[1, "Packed"], [2, "Has constructor"],
  [4, "Overloaded operators"], [8, "Nested"], [0x10, "Contains nested types"],
  [0x20, "Assignment operator"], [0x40, "Cast operator"], [0x80, "Forward reference"],
  [0x100, "Has destructor"]];
const POINTER_MODES = ["Pointer", "Reference", "Pointer to data member", "Pointer to method"];
const POINTER_KINDS = ["Near", "Far", "Huge", "Based on segment", "Based on value",
  "Based on segment of value", "Based on address of symbol", "Based on segment of symbol",
  "Based on type", "Based on self", "Near 32-bit", "Far 32-bit"];
const CALLING_CONVENTIONS: Readonly<Partial<Record<number, string>>> = {
  0: "Near C", 1: "Far C", 2: "Near Pascal", 3: "Far Pascal", 4: "Near fastcall",
  5: "Far fastcall", 7: "Near stdcall", 8: "Far stdcall", 9: "Near syscall",
  10: "Far syscall", 11: "Thiscall", 12: "MIPS call", 13: "Generic"
};
const AGGREGATE_KINDS: Readonly<Partial<Record<number, string>>> = {
  4: "Class", 5: "Structure", 7: "Enum"
};

const flagsText = (value: number | undefined, flags: FlagNames): string => {
  if (value === undefined) return "Not decoded";
  const names = flags.filter(([mask]) => value & mask).map(([, name]) => name);
  if (value & ~flags.reduce((mask, [bit]) => mask | bit, 0)) names.push("Unknown bits");
  return names.length ? names.join(", ") : "None";
};

const callingConvention = (value: number | undefined): string => {
  if (value === undefined) return "Not decoded";
  return [CALLING_CONVENTIONS[value & 0x3f] ?? "Unknown calling convention",
    ...(value & 0x40 ? ["Variable arguments"] : []),
    ...(value & 0x80 ? ["Unknown flags"] : [])].join(", ");
};

const pointerStatistics = (body: Td32TypeBody): Statistic[] => {
  const value = body.attributes;
  return [["Pointer mode", value === undefined ? "Not decoded"
    : POINTER_MODES[value >> 5 & 7] ?? "Unknown pointer mode", 1],
  ["Pointer representation", value === undefined ? "Not decoded"
    : POINTER_KINDS[value & 0x1f] ?? "Unknown pointer representation", 1],
  ["Pointer qualifiers", flagsText(value === undefined ? undefined : value & 0xff00, POINTER_FLAGS), 1]];
};

const procedureStatistics = (body: Td32TypeBody): Statistic[] => [
  ["Calling convention", callingConvention(body.callingConvention), 1],
  ["Procedure parameter count", body.parameterCount === undefined ? "Not decoded" : String(body.parameterCount), 1],
  ["Function attribute byte", body.functionAttributes === undefined ? "Not decoded"
    : body.functionAttributes === 0 ? "Zero" : "Nonzero (meaning unresolved)", 1]
];

const argumentStatistics = (body: Td32TypeBody): Statistic[] => body.argumentTypes === undefined
  ? [["Argument lists", "Not decoded", 1]]
  : [["Argument-list length", String(body.argumentTypes.length), 1],
    ["Arguments", "Total", body.argumentTypes.length]];

const bitFieldStatistics = (body: Td32TypeBody): Statistic[] => [
  ["Bit-field length", body.bitLength === undefined ? "Not decoded" : `${body.bitLength} bits`, 1],
  ["Bit-field position", body.bitPosition === undefined ? "Not decoded" : `${body.bitPosition} bits`, 1]
];

const BODY_STATISTICS: Readonly<Partial<Record<number, (body: Td32TypeBody) => Statistic[]>>> = {
  1: body => [["Modifier qualifiers", flagsText(body.attributes, MODIFIER_FLAGS), 1]],
  2: pointerStatistics, 8: procedureStatistics, 9: procedureStatistics,
  0x201: argumentStatistics, 0x206: bitFieldStatistics,
  0x204: body => [["Field-list members", "Total", body.fields?.length ?? 0]],
  0x207: body => [["Method-list overloads", "Total", body.methods?.length ?? 0]],
  10: body => [["Vtable descriptors", "Total", body.descriptors?.length ?? 0]],
  0x34: body => [["Pascal closures", "Tail interpretation unresolved", body.closureTail ? 1 : 0]],
  0x35: body => [["Pascal properties", body.attributes === undefined ? "Not decoded"
    : body.attributes & 1 ? "Default" : "Non-default", 1]]
};

const addStatistic = (statistics: Map<string, Statistic>, [measure, value, count]: Statistic): void => {
  const key = `${measure}\0${value}`;
  statistics.set(key, [measure, value, (statistics.get(key)?.[2] ?? 0) + count]);
};

const appendStatistics = (record: TypeRecord, statistics: Map<string, Statistic>): void => {
  if (!record.body) { addStatistic(statistics, ["Type bodies", "Not decoded", 1]); return; }
  for (const statistic of BODY_STATISTICS[record.type]?.(record.body) ?? []) addStatistic(statistics, statistic);
  // Meaning is disputed between published decoders. Count nonzero slots without
  // promoting their raw IDs to relationships or publishing anonymous record rows.
  const unresolved = [record.body.relation12, record.body.relation14,
    record.body.relation16, record.body.relation20].filter(value => value !== undefined && value !== 0).length;
  if (unresolved) addStatistic(statistics, ["Unresolved relation slots", "Nonzero", unresolved]);
};

const aggregateSize = (record: TypeRecord): string => {
  if (record.type === 7) return "Not recorded";
  if (!record.body?.byteSize) return "Not decoded";
  return record.body.byteSize.value ?? "Numeric size not interpreted";
};

const appendAggregate = (record: TypeRecord, names: readonly string[], table: Td32Table,
  statistics: Map<string, Statistic>, generation: number, module: number): void => {
  const kind = AGGREGATE_KINDS[record.type];
  if (!kind) return;
  const name = record.nameIndex ? names[record.nameIndex - 1] : undefined;
  if (!name) {
    addStatistic(statistics, ["Aggregate names", record.nameIndex ? "Unresolved shared name" : "Unnamed", 1]);
    return;
  }
  table.rows.push([name, kind,
    aggregateSize(record), record.body?.count === undefined ? "Not decoded" : String(record.body.count),
    record.type === 7 ? "Not recorded" : flagsText(record.body?.attributes, STRUCTURE_FLAGS),
    String(generation), String(module)]);
};

const mergeMemberTables = (members: Map<string, Td32Table>, tables: Td32Table[]): void => {
  for (const table of tables) {
    const existing = members.get(table.key);
    if (existing) for (const row of table.rows) existing.rows.push(row);
    else members.set(table.key, table);
  }
};

export const buildTd32TypeSemanticsTables = (td32: PeTd32Info): Td32Table[] => {
  const aggregates: Td32Table = { key: "typeaggregates", title: "TD32 named classes, structures and enums",
    columns: ["Name", "Kind", "Bytes", "Members/values", "Attributes", "Directory", "Module"], rows: [] };
  const statistics = new Map<string, Statistic>();
  const members = new Map<string, Td32Table>();
  for (const [generation, directory] of td32.directories.entries()) {
    const shared = directory.subsections.flatMap(section => section.data?.kind === "names" ? [section.data.names] : []);
    for (const section of directory.subsections) {
      if (section.data?.kind !== "types") continue;
      mergeMemberTables(members, buildTd32MemberTables(section.data, shared.length === 1 ? shared[0]! : [],
        generation + 1, section.module));
      for (const record of section.data.records) {
        appendAggregate(record, shared.length === 1 ? shared[0]! : [], aggregates,
          statistics, generation + 1, section.module);
        appendStatistics(record, statistics);
      }
    }
  }
  return [aggregates, ...members.values(), { key: "typestatistics", title: "TD32 type characteristics",
    columns: ["Measure", "Value", "Count"], rows: [...statistics.values()].map(([measure, value, count]) =>
      [measure, value, String(count)]) }].filter(table => table.rows.length);
};
