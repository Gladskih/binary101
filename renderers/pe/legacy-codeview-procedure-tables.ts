import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewProcedure } from "../../analyzers/pe/debug/legacy-codeview-procedure-symbols.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import { legacyCodeViewSymbolName } from "./legacy-codeview-kinds.js";
import { iterateLegacyCodeViewSymbols } from "./legacy-codeview-symbol-walk.js";

// CV_PROCFLAGS bit meanings from Microsoft's pinned cvinfo.h.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L3038
const PROCEDURE_FLAGS = [
  [1, "Frame pointer present"], [2, "Interrupt return"], [4, "Far return"],
  [8, "Never returns"], [16, "Not reached"], [32, "Custom calling convention"],
  [64, "No inline"], [128, "Optimized debug information"]
] as const;

const flagsText = (flags: number | undefined): string => flags === undefined ? "unavailable"
  : PROCEDURE_FLAGS.filter(([mask]) => (flags & mask) !== 0).map(([, name]) => name).join(", ") || "None";

const referenceText = (procedure: LegacyCodeViewProcedure): string =>
  procedure.reference === undefined ? "unavailable"
    : `${procedure.referenceKind === "typeIndex" ? "Type index" : "Procedure ID"} ${procedure.reference}`;

const locationText = (procedure: LegacyCodeViewProcedure): string => procedure.storedLocation === undefined
  ? "unavailable" : `${procedure.storedLocation.segment}:${procedure.storedLocation.offset}`;

const debugSpanText = (procedure: LegacyCodeViewProcedure): string =>
  procedure.debugStart === undefined || procedure.debugEnd === undefined ? "unavailable"
    : `${procedure.debugStart} to ${procedure.debugEnd}`;

const scopeOffsetsText = (procedure: LegacyCodeViewProcedure): string => procedure.scopeOffsets === undefined
  ? "unavailable" : `parent ${procedure.scopeOffsets.parent}; end ${procedure.scopeOffsets.end}; ` +
    `next ${procedure.scopeOffsets.next}`;

/** Show stored procedure bytes and raw references without resolving image or scope addresses. */
export const buildLegacyCodeViewProcedureTables = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const table: LegacyCodeViewTable = { key: "procedureSymbols", title: "Procedure symbols",
    columns: ["Directory", "Module", "Container", "Procedure kind", "Name", "Type or ID link",
      "Stored segment:offset", "Code length", "Debug span", "Raw parent/end/next offsets", "Flags"],
    rows: [] };
  info.directories.forEach((directory, directoryIndex) => {
    for (const section of directory.subsections) {
      if (!section.data) continue;
      const encoding = section.data.kind === "symbols" || section.data.kind === "types"
        ? section.data.encoding : undefined;
      for (const { record, container } of iterateLegacyCodeViewSymbols(section.data)) {
        if (!record.procedure) continue;
        table.rows.push([String(directoryIndex + 1), String(section.module), container ?? "(top level)",
          legacyCodeViewSymbolName(record.type, encoding), record.name ?? "(name unavailable)",
          referenceText(record.procedure), locationText(record.procedure),
          record.procedure.codeLength === undefined ? "unavailable" : String(record.procedure.codeLength),
          debugSpanText(record.procedure), scopeOffsetsText(record.procedure), flagsText(record.procedure.flags)]);
      }
    }
  });
  return table.rows.length ? [table] : [];
};
