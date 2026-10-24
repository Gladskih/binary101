import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import type { LegacyCodeViewTypeRecord, LegacyCodeViewTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { createCodeViewTypeFormatter, indexCodeViewTypes } from "./codeview-type-names.js";
import type { CodeViewTypeLinks } from "../../analyzers/pe/debug/legacy-codeview-type-links.js";

// CV_BuildInfo_e, lfStringId and lfUdt[Mod]SrcLine in Microsoft's cvinfo.h.
// A module source reference is a string-table offset, not an LF_STRING_ID.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
const BUILD_FIELDS = ["Current directory", "Build tool", "Source file", "Program database file", "Command arguments"];

interface CodeViewMetadataNamespace {
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>;
  formatType: (index: number) => string;
}

const metadataNamespace = (indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>): CodeViewMetadataNamespace =>
  ({ indexed, formatType: createCodeViewTypeFormatter(indexed) });

const stringText = (record: LegacyCodeViewTypeRecord, index: number): string => {
  const shape = record.shape;
  if (shape?.kind !== "stringId") return `type #${index} is not a string ID`;
  const text = record.strings?.[0];
  if (text === undefined) return `string ID #${index} has no stored text`;
  return shape.substrings ? `stored text: ${text}; substring list #${shape.substrings}` : text || "(empty)";
};

const storedString = (index: number, indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>): string => {
  if (index === 0) return "(none)";
  const record = indexed.get(index);
  return record ? stringText(record, index) : `${record === null ? "ambiguous" : "missing"} string ID #${index}`;
};

const buildRows = (indices: readonly number[], build: number,
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>): string[][] =>
  indices.length ? indices.map((index, position) => [String(build),
    BUILD_FIELDS[position] ?? `Additional argument ${position + 1}`, storedString(index, indexed)])
    : [[String(build), "Arguments", "(empty)"]];

const sourceRow = (shape: Extract<CodeViewTypeLinks, { kind: "sourceLine" }>,
  namespace: CodeViewMetadataNamespace): string[] => [namespace.formatType(shape.typeIndex),
  shape.module === undefined ? storedString(shape.source, namespace.indexed)
    : `module ${shape.module} string-table offset #${shape.source} (external)`, String(shape.line)];

const typeServerRow = (record: LegacyCodeViewTypeRecord,
  shape: Extract<CodeViewTypeLinks, { kind: "typeServer" }>): string[] => [
  record.strings === undefined ? "(file name unavailable)" : record.strings[0] || "(empty)",
  shape.identity.kind === "guid" ? `GUID ${shape.identity.value}`
    : `Signature 0x${shape.identity.value.toString(16).padStart(8, "0")}`, String(shape.age)
];

const metadataRows = (data: LegacyCodeViewTypes): Map<string, string[][]> => {
  const indexed = indexCodeViewTypes(data.records);
  const namespace = metadataNamespace(indexed);
  const external = metadataNamespace(new Map());
  const rows = new Map<string, string[][]>([
    ["buildInfo", []], ["typeSources", []], ["stringComponents", []], ["typeServers", []]
  ]);
  let build = 0;
  for (const record of data.records) {
    const local = record.index !== undefined && indexed.get(record.index) === record ? namespace : external;
    const shape = record.shape;
    switch (shape?.kind) {
      case "buildInfo": rows.get("buildInfo")!.push(...buildRows(shape.indices, ++build, local.indexed)); break;
      case "sourceLine": rows.get("typeSources")!.push(sourceRow(shape, local)); break;
      case "typeServer": rows.get("typeServers")!.push(typeServerRow(record, shape)); break;
      case "stringList": rows.get("stringComponents")!.push(...shape.indices.map((index, position) =>
        [String(record.index ?? "unresolved"), String(position + 1), storedString(index, local.indexed)])); break;
    }
  }
  return rows;
};

export const buildCodeViewBuildTables = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const tables: LegacyCodeViewTable[] = [
    { key: "buildInfo", title: "Build information", columns: ["Directory", "Module", "Build", "Field", "Value"], rows: [] },
    { key: "typeSources", title: "Type definition sources",
      columns: ["Directory", "Module", "Type", "Source file", "Source line"], rows: [] },
    { key: "stringComponents", title: "String components",
      columns: ["Directory", "Module", "String list", "Component", "Stored text"], rows: [] },
    { key: "typeServers", title: "PDB type server identities",
      columns: ["Directory", "Module", "PDB file", "Identity", "PDB age"], rows: [] }
  ];
  info.directories.forEach((directory, position) => {
    for (const section of directory.subsections) {
      if (section.data?.kind !== "types" || section.data.encoding) continue;
      const rows = metadataRows(section.data);
      for (const table of tables) for (const row of rows.get(table.key)!) {
        table.rows.push([String(position + 1), String(section.module), ...row]);
      }
    }
  });
  return tables.filter(table => table.rows.length);
};
