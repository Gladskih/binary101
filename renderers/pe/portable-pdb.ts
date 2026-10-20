import type { PortablePdbInfo, PortablePdbLocal } from "../../analyzers/pe/debug/portable-pdb-types.js";
import { PortablePdbTypeNames } from "../../analyzers/pe/debug/portable-pdb-type-names.js";
import type { PortablePdbConstant } from "../../analyzers/pe/debug/portable-pdb-constants.js";
import type { PeClrMetadataTables } from "../../analyzers/pe/clr/types.js";
import { renderPortablePdbCustom } from "./portable-pdb-custom.js";
import { renderPortablePdbImports } from "./portable-pdb-imports.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";

// Language IDs, hash algorithms and custom record kinds are specified by Portable PDB.
// https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md
const LANGUAGE_NAMES: Record<string, string> = {
  "3f5162f8-07c6-11d3-9053-00c04fa302a1": "C#",
  "3a12d0b8-c26c-11d0-b442-00a0244a1dd2": "Visual Basic",
  "ab4f38c9-b6e6-43ba-be3b-58080b2ccce3": "F#"
};
const createDocumentTableModel = (pdb: PortablePdbInfo, id: string): PagedSortableTableModel => ({
  id, pageSize: 100, rowCount: pdb.documents.length,
  columns: [{ label: "Source file" }, { label: "Language" }, { label: "Source checksum" }],
  rowAt: index => {
    const document = pdb.documents[index];
    if (!document) return null;
    const algorithm = ({
      "ff1816ec-aa5e-4d10-87f7-6f4963833460": "SHA-1",
      "8829d00f-11b8-4213-878b-770e8597ac16": "SHA-256",
      "d99cfeb1-8c43-444a-8a6c-b61269d2a0bf": "SHA-384",
      "ef2d1afc-6550-46d6-b14b-d70afe9a5566": "SHA-512"
    } as Record<string, string>)[document.hashAlgorithm ?? ""] ?? "Other or unspecified";
    return { cells: [
      { html: escapeHtml(document.name ?? "(unreadable name)") },
      { html: LANGUAGE_NAMES[document.language ?? ""] ?? "Other or unspecified" },
      { html: `${algorithm} (${document.hashSize ?? "unknown"} bytes)` }
    ] };
  },
  sortValueAt: (index, column) => {
    const document = pdb.documents[index];
    return document ? [document.name, LANGUAGE_NAMES[document.language ?? ""], document.hashAlgorithm][column] ?? "" : "";
  }
});

const embeddedPdb = (pe: PeWindowsParseResult, index: number): PortablePdbInfo | undefined =>
  pe.debug?.entries?.[index]?.embeddedPortablePdb?.portablePdb;

export const getPortablePdbTableModel = (
  pe: PeWindowsParseResult, tableId: string
): PagedSortableTableModel | null => {
  const match = /^pe-debug-entry-(\d+)-(documents|locals)$/.exec(tableId);
  if (!match) return null;
  const pdb = embeddedPdb(pe, Number(match[1]));
  if (!pdb) return null;
  return match[2] === "locals" ? createLocalTableModel(pdb, tableId, pe.clr?.meta?.tables) : createDocumentTableModel(pdb, tableId);
};

const constantText = (constant: PortablePdbConstant): string => {
  if (constant.data) return constant.data.length ? `Type-dependent value (${constant.data.length} bytes)` : "Default value";
  if (constant.typeCode === 3 || constant.typeCode === 14) return JSON.stringify(constant.value);
  return Object.is(constant.value, -0) ? "-0" : String(constant.value);
};

const localDetails = (local: PortablePdbLocal, names: PortablePdbTypeNames): string => {
  if (local.kind === "constant") {
    if (!local.constant) return `Signature: ${local.signatureSize ?? "unknown"} bytes`;
    const typeName = names.get(local.constant.typeReference) ?? ({
      2: "bool", 3: "char", 4: "int8", 5: "uint8", 6: "int16", 7: "uint16", 8: "int32", 9: "uint32",
      10: "int64", 11: "uint64", 12: "float32", 13: "float64", 14: "string", 17: "Value type", 18: "Reference type", 28: "object"
    } as Record<number, string>)[local.constant.typeCode] ?? "Constant";
    return `${typeName}: ${constantText(local.constant)}`;
  }
  // LocalVariableAttributes.DebuggerHidden is bit 0; other bits are reserved.
  return `Slot ${local.slot}${local.attributes & 1 ? "; hidden from debugger" : ""}`;
};

const createLocalTableModel = (
  pdb: PortablePdbInfo, id: string, metadata: PeClrMetadataTables | undefined
): PagedSortableTableModel => {
  const names = new PortablePdbTypeNames(metadata);
  return {
  id, pageSize: 100, rowCount: pdb.locals.length,
  columns: [{ label: "Local symbol" }, { label: "Kind" }, { label: "Details" }],
  rowAt: index => {
    const local = pdb.locals[index];
    return local ? { cells: [
      { html: escapeHtml(local.name ?? "(unreadable name)") },
      { html: local.kind === "variable" ? "Variable" : "Constant" },
      { html: escapeHtml(localDetails(local, names)) }
    ] } : null;
  },
  sortValueAt: (index, column) => {
    const local = pdb.locals[index];
    return local ? [local.name, local.kind, localDetails(local, names)][column] ?? "" : "";
  }
  };
};

export const renderPortablePdb = (
  pdb: PortablePdbInfo, out: string[], entryIndex = 0, metadata?: PeClrMetadataTables
): void => {
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Source documents", String(pdb.documents.length)));
  out.push(renderDefinitionRow("Methods with sequence points", String(pdb.methodsWithSequencePoints),
    "Methods with source mapping blobs, not a count of all functions in the PE."));
  out.push(renderDefinitionRow("Visible sequence points", String(pdb.sequencePoints.visible),
    "IL locations mapped to source lines and columns."));
  out.push(renderDefinitionRow("Hidden sequence points", String(pdb.sequencePoints.hidden),
    "Compiler-generated locations normally skipped by source debuggers."));
  out.push(`</dl><table class="table"><thead><tr><th>Debug metadata table</th>` +
    `<th class="peNumeric">Parsed rows</th><th class="peNumeric">Declared rows</th></tr></thead><tbody>`);
  pdb.tables.forEach(table => out.push(`<tr><td>${escapeHtml(table.name)}</td>` +
    `<td class="peNumeric">${table.parsedRows}</td><td class="peNumeric">${table.declaredRows}</td></tr>`));
  out.push(`</tbody></table>`);
  const languages = new Map<string, number>();
  pdb.documents.forEach(document => {
    const language = LANGUAGE_NAMES[document.language ?? ""] ?? "Other or unspecified language";
    languages.set(language, (languages.get(language) ?? 0) + 1);
  });
  if (languages.size) {
    out.push(`<dl>`);
    languages.forEach((count, name) => out.push(renderDefinitionRow(
      `Source documents: ${name}`, String(count))));
    out.push(`</dl>`);
  }
  renderPortablePdbCustom(pdb, out, entryIndex, metadata);
  if (pdb.documents.length) out.push(renderAutoPagedSortableTable(
    createDocumentTableModel(pdb, `pe-debug-entry-${entryIndex}-documents`)));
  if (pdb.locals.length) out.push(renderAutoPagedSortableTable(
    createLocalTableModel(pdb, `pe-debug-entry-${entryIndex}-locals`, metadata)));
  renderPortablePdbImports(pdb, out, entryIndex, metadata);
};
