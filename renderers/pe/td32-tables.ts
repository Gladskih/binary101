import type { PeTd32Info } from "../../analyzers/pe/debug/td32.js";
import { buildTd32SymbolTables } from "./td32-symbol-tables.js";
import { buildTd32TypeSemanticsTables } from "./td32-type-semantics-tables.js";
import { td32SymbolKind as symbolKind } from "./td32-symbol-properties.js";

export interface Td32Table { key: string; title: string; columns: string[]; rows: string[][]; }

// TD32 names are indexed from 1. Never substitute a guessed name for a dangling reference.
const resolveName = (names: readonly string[], index: number): string => index === 0
  ? "(unnamed)" : names[index - 1] ?? `(unresolved name #${index})`;
const TYPE_KINDS: Readonly<Partial<Record<number, string>>> = {
  1: "Modifier", 2: "Pointer", 3: "Array", 4: "Class", 5: "Structure", 6: "Union", 7: "Enum",
  8: "Procedure", 9: "Member function", 10: "Virtual table shape", 0x201: "Arguments",
  0x204: "Fields", 0x205: "Derived classes", 0x206: "Bit field", 0x207: "Methods"
};
const typeKind = (type: number): string => TYPE_KINDS[type] ?? `Producer-specific type kind ${type}`;
type Subsection = PeTd32Info["directories"][number]["subsections"][number];
const SECTION_KINDS: Readonly<Partial<Record<number, string>>> = {
  0x120: "Module", 0x121: "Module types", 0x124: "Symbols", 0x125: "Aligned symbols",
  0x127: "Source files", 0x129: "Global symbols", 0x12b: "Global types", 0x130: "Shared names"
};

const moduleRows = (section: Subsection, names: readonly string[], generation: string): string[][] => {
  const data = section.data;
  if (data?.kind !== "module") return [];
  return [[generation, String(section.module), resolveName(names, data.nameIndex),
    String(data.segments.filter(segment => segment.flags === 1).length),
    String(data.segments.filter(segment => segment.flags === 0).length),
    String(data.segments.reduce((size, segment) => size + segment.size, 0))]];
};

const sourceRows = (section: Subsection, names: readonly string[], generation: string): string[][] => {
  const data = section.data;
  if (data?.kind !== "source") return [];
  return data.files.map(file => {
    const lines = file.segments.flatMap(segment => segment.lines.map(line => line.line));
    return [generation, String(section.module), resolveName(names, file.nameIndex),
      String(file.segments.length), String(lines.length), String(new Set(lines).size)];
  });
};

const symbolRows = (section: Subsection, names: readonly string[], generation: string): string[][] => {
  const data = section.data;
  if (data?.kind !== "symbols") return [];
  return data.records.flatMap(record => record.nameIndex !== undefined || record.compiler !== undefined
    ? [[generation, String(section.module), symbolKind(record.type),
      record.compiler ?? resolveName(names, record.nameIndex!)]] : []);
};

const appendRows = (table: Td32Table, rows: string[][]): void => {
  for (const row of rows) table.rows.push(row);
};

const appendNamedRows = (section: Subsection, names: readonly string[], generation: string,
  tables: Td32Table[]): void => {
  const data = section.data;
  if (data?.kind === "names") data.names.forEach((name, index) =>
    tables[1]!.rows.push([generation, String(index + 1), name]));
  appendRows(tables[2]!, moduleRows(section, names, generation));
  appendRows(tables[3]!, sourceRows(section, names, generation));
  appendRows(tables[4]!, symbolRows(section, names, generation));
};

const sharedNames = (directory: PeTd32Info["directories"][number]): readonly string[] => {
  const names = directory.subsections.flatMap(section => section.data?.kind === "names" ? [section.data.names] : []);
  return names.length === 1 ? names[0]! : [];
};

const countSymbols = (section: Subsection, counts: Map<number, number>): void => {
  if (section.data?.kind !== "symbols") return;
  for (const record of section.data.records) counts.set(record.type, (counts.get(record.type) ?? 0) + 1);
};

const appendTypes = (section: Subsection, names: readonly string[], generation: string,
  tables: Td32Table[]): void => {
  if (section.data?.kind !== "types") return;
  const counts = new Map<number, number>();
  for (const record of section.data.records) {
    counts.set(record.type, (counts.get(record.type) ?? 0) + 1);
    if (record.nameIndex !== undefined) tables[6]!.rows.push([generation, String(section.module),
      String(record.index), typeKind(record.type), resolveName(names, record.nameIndex)]);
  }
  for (const [type, count] of counts) tables[7]!.rows.push([
    generation, String(section.module), typeKind(type), String(count)]);
};

const directoryRows = (directory: PeTd32Info["directories"][number], generation: string,
  tables: Td32Table[]): void => {
  const strings = sharedNames(directory);
  const counts = new Map<number, number>();
  for (const section of directory.subsections) {
    tables[0]!.rows.push([generation, String(section.module), SECTION_KINDS[section.type] ?? `Unrecognized kind ${section.type}`,
      String(section.size), section.data?.kind ?? "Not decoded"]);
    appendNamedRows(section, strings, generation, tables);
    appendTypes(section, strings, generation, tables);
    countSymbols(section, counts);
  }
  for (const [type, count] of counts) tables[5]!.rows.push([generation, symbolKind(type), String(count)]);
};

export const buildTd32Tables = (td32: PeTd32Info): Td32Table[] => {
  const tables: Td32Table[] = [
    { key: "inventory", title: "TD32 subsection inventory", columns: ["Directory", "Module", "Subsection kind", "Bytes", "Analysis"], rows: [] },
    { key: "names", title: "TD32 shared names", columns: ["Directory", "Index", "Name"], rows: [] },
    { key: "modules", title: "TD32 modules", columns: ["Directory", "Module", "Name", "Code segments", "Data segments", "Contributed bytes"], rows: [] },
    { key: "source", title: "TD32 source files", columns: ["Directory", "Module", "Source file", "Segments", "Line/address pairs", "Distinct source lines"], rows: [] },
    { key: "symbols", title: "TD32 named symbols", columns: ["Directory", "Module", "Symbol kind", "Name"], rows: [] },
    { key: "kinds", title: "TD32 symbol statistics", columns: ["Directory", "Symbol kind", "Records"], rows: [] },
    { key: "types", title: "TD32 named types", columns: ["Directory", "Module", "Index", "Type kind", "Name"], rows: [] },
    { key: "typekinds", title: "TD32 type statistics", columns: ["Directory", "Module", "Type kind", "Records"], rows: [] }
  ];
  td32.directories.forEach((directory, index) => directoryRows(directory, String(index + 1), tables));
  return [...tables.filter(table => table.rows.length), ...buildTd32SymbolTables(td32),
    ...buildTd32TypeSemanticsTables(td32)];
};
