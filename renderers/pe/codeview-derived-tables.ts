import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import type { LegacyCodeViewTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { createCodeViewTypeFormatter, indexCodeViewTypes } from "./codeview-type-names.js";

const derivedRows = (data: LegacyCodeViewTypes): string[][] => {
  const indexed = indexCodeViewTypes(data.records);
  const format = createCodeViewTypeFormatter(indexed);
  return data.records.flatMap(record => {
    if (record.index === undefined || indexed.get(record.index) !== record) return [];
    const shape = record.shape;
    if (shape?.kind !== "aggregate" || !shape.derivedTypes) return [];
    const list = indexed.get(shape.derivedTypes)?.shape;
    return list?.kind === "derived" ? list.indices.map(index => [format(record.index!), format(index)]) : [];
  });
};

export const buildCodeViewDerivedTables = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const table: LegacyCodeViewTable = { key: "derivedTypes", title: "Derived type relationships",
    columns: ["Directory", "Module", "Base type", "Derived type"], rows: [] };
  info.directories.forEach((directory, index) => {
    for (const section of directory.subsections) {
      if (section.data?.kind !== "types" || section.data.encoding) continue;
      for (const row of derivedRows(section.data)) table.rows.push([String(index + 1), String(section.module), ...row]);
    }
  });
  return table.rows.length ? [table] : [];
};
