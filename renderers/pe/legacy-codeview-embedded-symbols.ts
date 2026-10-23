import type { PeLegacyCodeViewInfo, LegacyCodeViewData } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import { legacyCodeViewSymbolName } from "./legacy-codeview-kinds.js";
import { iterateLegacyCodeViewSymbols } from "./legacy-codeview-symbol-walk.js";

const appendSection = (data: LegacyCodeViewData, names: LegacyCodeViewTable,
  statistics: LegacyCodeViewTable, directory: number, module: number): void => {
  const counts = new Map<string, Map<number, number>>();
  for (const { record, container } of iterateLegacyCodeViewSymbols(data)) {
    if (container === undefined) continue;
    if (record.name !== undefined) names.rows.push([String(directory), String(module), container,
      legacyCodeViewSymbolName(record.type), record.name || "(unnamed)"]);
    const group = counts.get(container) ?? new Map<number, number>();
    group.set(record.type, (group.get(record.type) ?? 0) + 1);
    counts.set(container, group);
  }
  for (const [container, group] of counts) for (const [type, count] of group) {
    statistics.rows.push([String(directory), String(module), container, legacyCodeViewSymbolName(type), String(count)]);
  }
};

export const buildLegacyCodeViewEmbeddedSymbolTables = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const names: LegacyCodeViewTable = { key: "embeddedSymbols", title: "Embedded symbol names",
    columns: ["Directory", "Module", "Container", "Symbol kind", "Name"], rows: [] };
  const statistics: LegacyCodeViewTable = { key: "embeddedSymbolStats", title: "Embedded symbol statistics",
    columns: ["Directory", "Module", "Container", "Symbol kind", "Records"], rows: [] };
  info.directories.forEach((directory, index) => {
    for (const section of directory.subsections) if (section.data) {
      appendSection(section.data, names, statistics, index + 1, section.module);
    }
  });
  return [names, statistics].filter(table => table.rows.length > 0);
};
