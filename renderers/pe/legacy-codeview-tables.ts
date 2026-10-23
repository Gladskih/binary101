import type { PeLegacyCodeViewInfo, LegacyCodeViewData } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewSource } from "../../analyzers/pe/debug/legacy-codeview-source.js";
import type { LegacyCodeViewFiles } from "../../analyzers/pe/debug/legacy-codeview-modules.js";
import { legacyCodeViewSubsectionName, legacyCodeViewSymbolName, legacyCodeViewTypeName } from "./legacy-codeview-kinds.js";
import { legacyCodeViewFieldName } from "./legacy-codeview-kinds.js";
import type { LegacyCodeViewTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { buildLegacyCodeViewIndexTables } from "./legacy-codeview-index-tables.js";
import { buildLegacyCodeViewSymbolStringTables } from "./legacy-codeview-symbol-tables.js";
import { buildLegacyCodeViewEmbeddedSymbolTables } from "./legacy-codeview-embedded-symbols.js";
import { buildLegacyCodeViewDiscardedStatistics } from "./legacy-codeview-discarded-statistics.js";

export interface LegacyCodeViewTable { key: string; title: string; columns: string[]; rows: string[][]; }
interface DirectoryNames { libraries: readonly string[] | null; segments: ReadonlyMap<number, string>; }

const directoryNames = (contents: readonly (LegacyCodeViewData | undefined)[]): DirectoryNames => {
  let libraries: readonly string[] | null = null;
  const segments = new Map<number, string>();
  for (const data of contents) {
    if (data?.kind === "libraries") libraries = data.names;
    if (data?.kind === "segmentNames") for (const name of data.names) segments.set(name.offset, name.name);
  }
  return { libraries, segments };
};

const sourceRows = (source: LegacyCodeViewSource): string[][] => source.files.map(file => {
  const lines = file.segments.flatMap(segment => segment.lines.map(line => line.line));
  const distinct = new Set(lines);
  return [file.name, String(file.segments.length), String(lines.length), String(distinct.size)];
});

const fileRows = (files: LegacyCodeViewFiles): string[][] => {
  // Difference counts avoid expanding overlapping module reference ranges.
  const counts = new Int32Array(files.names.length + 1);
  for (const module of files.modules) { counts[module.first]!++; counts[module.first + module.count]!--; }
  let count = 0;
  return files.names.map((name, index) => { count += counts[index]!; return [name, String(count)]; });
};

const segmentAccess = (flags: number): string => [
  flags & 1 ? "read" : "", flags & 2 ? "write" : "", flags & 4 ? "execute" : "",
  flags & 8 ? "32-bit" : "", flags & 0x100 ? "selector" : "", flags & 0x200 ? "absolute" : "",
  flags & 0x1000 ? "group" : ""
].filter(Boolean).join(", ") || "No access flags";

const recordRows = (data: LegacyCodeViewData): string[][] => {
  if (data.kind === "publics") return data.names.map(name => [name]);
  if (data.kind === "symbols") return data.records.flatMap(record => record.name == null ? [] :
    [[legacyCodeViewSymbolName(record.type), record.name]]);
  if (data.kind === "types") return data.records.flatMap(record => [
    ...(record.name == null ? [] : [[legacyCodeViewTypeName(record.type), record.name]]),
    ...(record.uniqueName == null ? [] : [[`${legacyCodeViewTypeName(record.type)} (decorated)`, record.uniqueName]])
  ]);
  return [];
};

const namedRows = (data: LegacyCodeViewData): string[][] => {
  if (data.kind === "source") return sourceRows(data);
  if (data.kind === "files") return fileRows(data);
  if (data.kind === "oldLines") return data.files.map(file => [file.name, String(file.lines.length),
    String(new Set(file.lines.map(line => line.line)).size)]);
  if (data.kind === "frameMap") return [[String(data.frames.length), String(new Set(data.frames).size)]];
  if (data.kind === "libraries") return data.names.map((name, index) => [String(index), name || "(none)"]);
  if (data.kind === "segmentNames") return data.names.map(value => [value.name]);
  return recordRows(data);
};

const schemas: Record<LegacyCodeViewData["kind"], [string, string[]]> = {
  module: ["Modules", ["Name", "Library", "Style", "Segments", "Contributed bytes"]],
  libraries: ["Libraries", ["Index", "Name"]], segmentNames: ["Segment names", ["Name"]],
  segmentMap: ["Segments", ["Segment", "Name", "Class", "Bytes", "Attributes"]],
  source: ["Source mappings", ["File", "Segments", "Line/address pairs", "Distinct source lines"]],
  files: ["Source file index", ["File", "Referencing modules"]],
  symbols: ["Named symbols", ["Symbol kind", "Name"]], types: ["Named types", ["Type kind", "Name"]],
  publics: ["Public symbols", ["Name"]], oldLines: ["Legacy source mappings", ["File", "Line/address pairs", "Distinct source lines"]],
  frameMap: ["Segment-to-frame statistics", ["Mapped segments", "Distinct frames"]]
};

const dataRows = (data: LegacyCodeViewData, names: DirectoryNames): string[][] => {
  if (data.kind === "module") {
    return [[data.name, names.libraries ? (names.libraries[data.library] ?? `#${data.library}`) || "(none)" : `#${data.library}`,
      data.style, String(data.segments.length), String(data.segments.reduce((sum, segment) => sum + segment.size, 0))]];
  }
  if (data.kind !== "segmentMap") return namedRows(data);
  return data.segments.map((segment, index) => [String(index + 1),
    names.segments.get(segment.name) ?? "(unnamed)", names.segments.get(segment.className) ?? "(unnamed)",
    String(segment.size), segmentAccess(segment.flags)]);
};

const addMemberHistogram = (table: LegacyCodeViewTable, data: LegacyCodeViewTypes,
  directory: number, module: number): void => {
  const counts = new Map<number, number>();
  for (const record of data.records) for (const member of record.members ?? []) {
    counts.set(member.type, (counts.get(member.type) ?? 0) + 1);
  }
  for (const [type, count] of counts) table.rows.push([String(directory), String(module),
    "Type members", legacyCodeViewFieldName(type), String(count)]);
};

const addMemberNames = (tables: Map<string, LegacyCodeViewTable>, data: LegacyCodeViewData,
  directory: number, module: number): void => {
  if (data.kind !== "types") return;
  const table = tables.get("members") ?? { key: "members", title: "Member and enumerator names",
    columns: ["Directory", "Module", "Member kind", "Name"], rows: [] };
  for (const record of data.records) for (const member of record.members ?? []) {
    if (member.name === undefined) continue;
    table.rows.push([String(directory), String(module), legacyCodeViewFieldName(member.type), member.name || "(unnamed)"]);
  }
  tables.set("members", table);
};

const typeStringKind = (type: number, index: number): string => type === 2 || type === 0x1002
  ? "Pointer base type" : type === 0x151d ? (index === 0 ? "Virtual table name" : "Virtual method name")
    : legacyCodeViewTypeName(type);

const addTypeStrings = (tables: Map<string, LegacyCodeViewTable>, data: LegacyCodeViewData,
  directory: number, module: number): void => {
  if (data.kind !== "types") return;
  const table = tables.get("typeStrings") ?? { key: "typeStrings", title: "Stored type and ID strings",
    columns: ["Directory", "Module", "Record kind", "Text"], rows: [] };
  for (const record of data.records) (record.strings ?? []).forEach((text, index) => {
    table.rows.push([String(directory), String(module), typeStringKind(record.type, index), text || "(empty)"]);
  });
  tables.set("typeStrings", table);
};

const addHistogram = (table: LegacyCodeViewTable, data: LegacyCodeViewData,
  directory: number, module: number): void => {
  if (data.kind !== "symbols" && data.kind !== "types") return;
  const counts = new Map<number, number>();
  for (const record of data.records) counts.set(record.type, (counts.get(record.type) ?? 0) + 1);
  for (const [type, count] of counts) table.rows.push([String(directory), String(module),
    data.kind === "symbols" ? "Symbols" : "Types",
    data.kind === "symbols" ? legacyCodeViewSymbolName(type) : legacyCodeViewTypeName(type), String(count)]);
  if (data.kind === "types") addMemberHistogram(table, data, directory, module);
};

export const buildLegacyCodeViewTables = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const tables = new Map<string, LegacyCodeViewTable>();
  const inventory: LegacyCodeViewTable = { key: "inventory", title: "Subsection inventory",
    columns: ["Directory", "Subsection", "Records", "Payload bytes", "Decoded"], rows: [] };
  const histogram: LegacyCodeViewTable = { key: "records", title: "Symbol and type statistics",
    columns: ["Directory", "Module", "Category", "Record kind", "Records"], rows: [] };
  info.directories.forEach((directory, index) => {
    const names = directoryNames(directory.subsections.map(section => section.data));
    const groups = new Map<number, { count: number; size: number; decoded: number }>();
    for (const section of directory.subsections) {
      const group = groups.get(section.type) ?? { count: 0, size: 0, decoded: 0 };
      group.count++; group.size += section.size; group.decoded += Number(section.data != null);
      groups.set(section.type, group);
      if (!section.data) continue;
      const data = section.data;
      const rows = dataRows(data, names);
      const [title, columns] = schemas[data.kind];
      const table = tables.get(data.kind) ?? { key: data.kind, title, columns: ["Directory", "Module", ...columns], rows: [] };
      for (const row of rows) table.rows.push([String(index + 1), String(section.module), ...row]);
      tables.set(data.kind, table);
      addMemberNames(tables, data, index + 1, section.module);
      addTypeStrings(tables, data, index + 1, section.module);
      addHistogram(histogram, data, index + 1, section.module);
    }
    for (const [type, group] of groups) inventory.rows.push([String(index + 1), legacyCodeViewSubsectionName(type),
      String(group.count), String(group.size), `${group.decoded} / ${group.count}`]);
  });
  return [inventory, histogram, ...tables.values(), ...buildLegacyCodeViewIndexTables(info),
    ...buildLegacyCodeViewSymbolStringTables(info), ...buildLegacyCodeViewEmbeddedSymbolTables(info),
    ...buildLegacyCodeViewDiscardedStatistics(info)]
    .filter(table => table.rows.length > 0);
};
