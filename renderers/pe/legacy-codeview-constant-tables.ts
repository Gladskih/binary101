import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewConstant } from "../../analyzers/pe/debug/legacy-codeview-constant-symbols.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import { legacyCodeViewSymbolName } from "./legacy-codeview-kinds.js";
import { iterateLegacyCodeViewSymbols } from "./legacy-codeview-symbol-walk.js";

const numericText = (constant: LegacyCodeViewConstant): string => {
  if ("issue" in constant.numeric) return `Unavailable: ${constant.numeric.issue}`;
  if (constant.numeric.value !== undefined) return constant.numeric.value;
  return `Noninteger numeric leaf ${constant.numeric.leaf} (${constant.numeric.byteLength} bytes)`;
};

/** Keep stored constant values beside their symbol names and CodeView type indexes. */
export const buildLegacyCodeViewConstantTables = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const table: LegacyCodeViewTable = { key: "symbolConstants", title: "Stored symbol constants",
    columns: ["Directory", "Module", "Container", "Symbol kind", "Name", "Type index", "Stored value"],
    rows: [] };
  info.directories.forEach((directory, directoryIndex) => {
    for (const section of directory.subsections) {
      if (!section.data) continue;
      const encoding = section.data.kind === "symbols" || section.data.kind === "types"
        ? section.data.encoding : undefined;
      for (const { record, container } of iterateLegacyCodeViewSymbols(section.data)) {
        if (!record.constant) continue;
        table.rows.push([String(directoryIndex + 1), String(section.module), container ?? "(top level)",
          legacyCodeViewSymbolName(record.type, encoding), record.name ?? "(name unavailable)",
          record.constant.typeIndex === undefined ? "unavailable" : String(record.constant.typeIndex),
          numericText(record.constant)]);
      }
    }
  });
  return table.rows.length ? [table] : [];
};
