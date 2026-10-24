import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewDataSymbol } from "../../analyzers/pe/debug/legacy-codeview-data-symbols.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import { legacyCodeViewSymbolName } from "./legacy-codeview-kinds.js";
import { iterateLegacyCodeViewSymbols } from "./legacy-codeview-symbol-walk.js";
import { legacyCodeViewProcedureFlags } from "./legacy-codeview-procedure-tables.js";

const PUBLIC_FLAG_NAMES = [[1, "Code"], [2, "Function"], [4, "Managed"], [8, "MSIL"]] as const;

const dataTypeText = (data: LegacyCodeViewDataSymbol): string => data.typeIndex === undefined
  ? "unavailable" : `Type index ${data.typeIndex}`;

const locationText = (data: LegacyCodeViewDataSymbol): string => data.location === undefined
  ? "unavailable" : `${data.location.segment}:${data.location.offset}`;

const publicFlagsText = (data: LegacyCodeViewDataSymbol): string => {
  if (data.kind !== "public") return "(not public)";
  const flags = data.publicFlags;
  if (flags === undefined) return "unavailable";
  const known: string[] = PUBLIC_FLAG_NAMES.filter(([mask]) => (flags & mask) !== 0).map(([, name]) => name);
  const unknown = (flags & 0xfffffff0) >>> 0;
  if (unknown !== 0) known.push(`Unknown bits 0x${unknown.toString(16)}`);
  return known.join(", ") || "None";
};

const blockText = (data: LegacyCodeViewDataSymbol): string => data.kind !== "block" ? "not a block"
  : data.codeLength === undefined ? "unavailable" : String(data.codeLength);

const scopeText = (data: LegacyCodeViewDataSymbol): string => data.scopeOffsets === undefined
  ? "unavailable" : `parent ${data.scopeOffsets.parent}; end ${data.scopeOffsets.end}`;

const flagsText = (data: LegacyCodeViewDataSymbol): string => data.flags === undefined
  ? "unavailable" : legacyCodeViewProcedureFlags(data.flags);

/** Show stored symbol fields without resolving section numbers into image addresses. */
export const buildLegacyCodeViewDataSymbolTables = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const table: LegacyCodeViewTable = { key: "dataSymbols", title: "Data, public, block and label symbols",
    columns: ["Directory", "Module", "Container", "Symbol kind", "Name", "Type reference",
      "Stored segment:offset", "Code length", "Raw parent/end offsets", "Public flags", "Symbol flags"],
    rows: [] };
  info.directories.forEach((directory, directoryIndex) => {
    for (const section of directory.subsections) {
      if (!section.data) continue;
      const encoding = section.data.kind === "symbols" || section.data.kind === "types"
        ? section.data.encoding : undefined;
      for (const { record, container } of iterateLegacyCodeViewSymbols(section.data)) {
        if (!record.data) continue;
        table.rows.push([String(directoryIndex + 1), String(section.module), container ?? "(top level)",
          legacyCodeViewSymbolName(record.type, encoding), record.name ?? "(name unavailable)",
          dataTypeText(record.data), locationText(record.data), blockText(record.data),
          scopeText(record.data), publicFlagsText(record.data), flagsText(record.data)]);
      }
    }
  });
  return table.rows.length ? [table] : [];
};
