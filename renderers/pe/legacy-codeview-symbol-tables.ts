import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewSymbols } from "../../analyzers/pe/debug/legacy-codeview-symbols.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import { legacyCodeViewSymbolName } from "./legacy-codeview-kinds.js";

const pairedRows = (strings: readonly string[]): string[][] => {
  const rows: string[][] = [];
  for (let index = 0; index < strings.length; index += 2) {
    rows.push([strings[index] || "(empty key)", strings[index + 1] === undefined
      ? "(missing value)" : strings[index + 1] || "(empty)"]);
  }
  return rows;
};

const symbolTextRows = (record: LegacyCodeViewSymbols["records"][number]): string[][] => {
  const strings = record.strings ?? [];
  // Microsoft's C7Compile2 / C7Envblock consume command-block fields as pairs.
  // https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/cvdump/dumpsym7.cpp#L5849
  return ([0x1013, 0x1116, 0x113d].includes(record.type) ? pairedRows(strings)
    : strings.map((text, index) => [record.type === 0x1161
      ? (index === 0 ? "Source PDB" : "Destination PDB") : `String ${index + 1}`, text || "(empty)"]))
    .map(row => [legacyCodeViewSymbolName(record.type), ...row]);
};

export const buildLegacyCodeViewSymbolStringTables = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const table: LegacyCodeViewTable = { key: "symbolStrings", title: "Stored symbol strings",
    columns: ["Directory", "Module", "Symbol kind", "Field", "Text"], rows: [] };
  info.directories.forEach((directory, index) => {
    for (const section of directory.subsections) {
      if (section.data?.kind !== "symbols") continue;
      for (const record of section.data.records) for (const row of symbolTextRows(record)) {
        table.rows.push([String(index + 1), String(section.module), ...row]);
      }
    }
  });
  return table.rows.length ? [table] : [];
};
