import type { PeLegacyCodeViewInfo, LegacyCodeViewData } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewProcedure } from "../../analyzers/pe/debug/legacy-codeview-procedure-symbols.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import { legacyCodeViewSymbolName } from "./legacy-codeview-kinds.js";
import { iterateLegacyCodeViewSymbols, type LegacyCodeViewSymbolNode } from "./legacy-codeview-symbol-walk.js";
import { createCodeViewProcedureResolver,
  type CodeViewProcedureAddress } from "../../analyzers/pe/debug/codeview-procedure-addresses.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";

// CV_PROCFLAGS bit meanings from Microsoft's pinned cvinfo.h.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L3038
const PROCEDURE_FLAGS = [
  [1, "Frame pointer present"], [2, "Interrupt return"], [4, "Far return"],
  [8, "Never returns"], [16, "Not reached"], [32, "Custom calling convention"],
  [64, "No inline"], [128, "Optimized debug information"]
] as const;

export const legacyCodeViewProcedureFlags = (flags: number | undefined): string => flags === undefined ? "unavailable"
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

const addressCells = (address: CodeViewProcedureAddress, pe: PeWindowsParseResult): string[] =>
  address.reason !== undefined ? ["unresolved", "unavailable", address.reason]
    : [`0x${address.rva.toString(16)}`, `#${address.section} ${pe.sections[address.section - 1]!.name.value}`,
      "Full stored range fits the image section"];

const countAddress = (counts: Map<string, number>, address: CodeViewProcedureAddress,
  pe: PeWindowsParseResult): void => {
  const key = address.reason !== undefined ? `Unresolved: ${address.reason}`
    : `Resolved in #${address.section} ${pe.sections[address.section - 1]!.name.value}`;
  counts.set(key, (counts.get(key) ?? 0) + 1);
};

const addProcedureRows = (table: LegacyCodeViewTable, data: LegacyCodeViewData, directory: number,
  module: number, addressFields: (node: LegacyCodeViewSymbolNode) => string[]): void => {
  const encoding = data.kind === "symbols" || data.kind === "types" ? data.encoding : undefined;
  for (const node of iterateLegacyCodeViewSymbols(data)) {
    const { record, container } = node;
    if (!record.procedure) continue;
    table.rows.push([String(directory + 1), String(module), container ?? "(top level)",
      legacyCodeViewSymbolName(record.type, encoding), record.name ?? "(name unavailable)",
      referenceText(record.procedure), locationText(record.procedure),
      record.procedure.codeLength === undefined ? "unavailable" : String(record.procedure.codeLength),
      debugSpanText(record.procedure), scopeOffsetsText(record.procedure),
      legacyCodeViewProcedureFlags(record.procedure.flags), ...addressFields(node)]);
  }
};

const resolveNode = (node: LegacyCodeViewSymbolNode, directory: number,
  resolve: ReturnType<typeof createCodeViewProcedureResolver>): CodeViewProcedureAddress => {
  if (node.addressContext === "discarded") return { reason: "Discarded symbol does not identify current image code." };
  if (node.addressContext === "type") return { reason: "Type-embedded symbol address context is not established." };
  return resolve(directory, node.record.procedure!);
};

const prioritizeImageAddresses = (table: LegacyCodeViewTable): LegacyCodeViewTable => {
  const leading = ["Name", "Image RVA", "PE section", "Code length", "Address resolution"];
  const columns = [...leading, ...table.columns.filter(column => !leading.includes(column))];
  const indices = columns.map(column => table.columns.indexOf(column));
  return { ...table, columns, rows: table.rows.map(row => indices.map(index => row[index]!)) };
};

/** Keep stored references and resolve image ranges only from validated PE context. */
export const buildLegacyCodeViewProcedureTables = (info: PeLegacyCodeViewInfo,
  pe?: PeWindowsParseResult): LegacyCodeViewTable[] => {
  const resolve = pe ? createCodeViewProcedureResolver(info, pe.sections, pe.debug?.entries) : undefined;
  const counts = new Map<string, number>();
  const table: LegacyCodeViewTable = { key: "procedureSymbols", title: "Procedure symbols",
    columns: ["Directory", "Module", "Container", "Procedure kind", "Name", "Type or ID link",
      "Stored segment:offset", "Code length", "Debug span", "Raw parent/end/next offsets", "Flags",
      ...(pe ? ["Image RVA", "PE section", "Address resolution"] : [])],
    rows: [] };
  info.directories.forEach((directory, directoryIndex) => {
    for (const section of directory.subsections) {
      if (!section.data) continue;
      addProcedureRows(table, section.data, directoryIndex, section.module, node => {
        if (!resolve || !pe) return [];
        const address = resolveNode(node, directoryIndex, resolve);
        countAddress(counts, address, pe);
        return addressCells(address, pe);
      });
    }
  });
  if (!table.rows.length) return [];
  return [...(counts.size ? [{ key: "procedureAddresses", title: "Procedure address resolution",
    columns: ["Result", "Records"], rows: [...counts].map(([key, count]) => [key, String(count)]) }] : []),
  pe ? prioritizeImageAddresses(table) : table];
};
