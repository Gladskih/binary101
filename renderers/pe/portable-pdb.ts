import type { PortablePdbInfo, PortablePdbLocal } from "../../analyzers/pe/debug/portable-pdb-types.js";
import { humanSize } from "../../binary-utils.js";
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
const CUSTOM_NAMES: Record<string, string> = {
  "6da9a61e-f8c7-4874-be62-68bc5630df71": "Hoisted local scopes",
  "83c563c4-b4f3-47d5-b824-ba5441477ea8": "Dynamic local variables",
  "58b2eab6-209f-4e4e-a22c-b2d0f910c782": "Default namespace",
  "755f52a8-91c5-45be-b4b8-209571e552bd": "Edit and Continue local slots",
  "a643004c-0240-496f-a783-30d64f4979de": "Edit and Continue lambdas and closures",
  "ed9fdf71-8879-4747-8ed3-fe5ede3ce710": "Embedded source",
  "cc110556-a091-4d38-9fec-25ab9a351a6a": "Source Link",
  "7e4d4708-096e-4c5c-aeda-cb10ba6a740d": "Compilation references",
  "b5feec05-8cd0-4a83-96da-466284bb4bd8": "Compilation options",
  "932e74bc-dba9-4478-8d46-0f32a7bab3d3": "Type definition documents"
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

export const getPortablePdbTableModel = (
  pe: PeWindowsParseResult, tableId: string
): PagedSortableTableModel | null => {
  const match = /^pe-debug-entry-(\d+)-(documents|locals)$/.exec(tableId);
  if (!match) return null;
  const pdb = pe.debug?.entries?.[Number(match[1])]?.embeddedPortablePdb?.portablePdb;
  if (!pdb) return null;
  return match[2] === "locals" ? createLocalTableModel(pdb, tableId) : createDocumentTableModel(pdb, tableId);
};

const localDetails = (local: PortablePdbLocal): string => {
  if (local.kind === "constant") return `Signature: ${local.signatureSize ?? "unknown"} bytes`;
  // LocalVariableAttributes.DebuggerHidden is bit 0; other bits are reserved.
  return `Slot ${local.slot}${local.attributes & 1 ? "; hidden from debugger" : ""}`;
};

const createLocalTableModel = (pdb: PortablePdbInfo, id: string): PagedSortableTableModel => ({
  id, pageSize: 100, rowCount: pdb.locals.length,
  columns: [{ label: "Local symbol" }, { label: "Kind" }, { label: "Details" }],
  rowAt: index => {
    const local = pdb.locals[index];
    return local ? { cells: [
      { html: escapeHtml(local.name ?? "(unreadable name)") },
      { html: local.kind === "variable" ? "Variable" : "Constant" },
      { html: localDetails(local) }
    ] } : null;
  },
  sortValueAt: (index, column) => {
    const local = pdb.locals[index];
    return local ? [local.name, local.kind, localDetails(local)][column] ?? "" : "";
  }
});

const renderCustomRecords = (pdb: PortablePdbInfo, out: string[]): void => {
  const kinds = new Map<string, { count: number; bytes: number }>();
  for (const record of pdb.customRecords) {
    const name = CUSTOM_NAMES[record.kind ?? ""] ?? "Other custom debug information";
    const previous = kinds.get(name) ?? { count: 0, bytes: 0 };
    kinds.set(name, { count: previous.count + 1, bytes: previous.bytes + (record.size ?? 0) });
  }
  if (!kinds.size) return;
  out.push(`<table class="table"><thead><tr><th>Custom debug information</th>` +
    `<th class="peNumeric">Records</th><th class="peNumeric">Payload size</th></tr></thead><tbody>`);
  for (const [name, stats] of kinds) {
    out.push(`<tr><td>${escapeHtml(name)}</td><td class="peNumeric">${stats.count}</td>` +
      `<td class="peNumeric">${humanSize(stats.bytes)}</td></tr>`);
  }
  out.push(`</tbody></table><p class="smallNote">Custom records are inventoried by kind and size; ` +
    `their language-specific contents are not fully decoded. Source Link is never fetched.</p>`);
};

export const renderPortablePdb = (pdb: PortablePdbInfo, out: string[], entryIndex = 0): void => {
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
  renderCustomRecords(pdb, out);
  if (pdb.documents.length) out.push(renderAutoPagedSortableTable(
    createDocumentTableModel(pdb, `pe-debug-entry-${entryIndex}-documents`)));
  if (pdb.locals.length) out.push(renderAutoPagedSortableTable(
    createLocalTableModel(pdb, `pe-debug-entry-${entryIndex}-locals`)));
};
