import type { PortablePdbInfo, PortablePdbCustomRecord } from "../../analyzers/pe/debug/portable-pdb-types.js";
import type { PortablePdbCustomData } from "../../analyzers/pe/debug/portable-pdb-custom-types.js";
import { PORTABLE_PDB_CUSTOM_KINDS } from "../../analyzers/pe/debug/portable-pdb-custom-kinds.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import type { PeClrMetadataTables } from "../../analyzers/pe/clr/types.js";
import type { PortablePdbSource } from "../../analyzers/pe/debug/portable-pdb-source.js";
import { escapeHtml } from "../../html-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";

const textTable = <Row>(
  id: string, rows: readonly Row[], labels: string[], values: (row: Row) => string[]
): PagedSortableTableModel => ({
  id, pageSize: 100, rowCount: rows.length,
  columns: labels.map(label => ({ label, ...(/bytes$/i.test(label) ? { className: "peNumeric" } : {}) })),
  rowAt: index => {
    const row = rows[index];
    return row === undefined ? null : { cells: values(row).map((value, column) => ({
      html: escapeHtml(value), ...(/bytes$/i.test(labels[column]!) ? { className: "peNumeric" } : {})
    })) };
  },
  sortValueAt: (index, column) => rows[index] === undefined ? "" : values(rows[index]!)[column] ?? ""
});

const referenceFlags = (flags: number): string =>
  `${flags & 1 ? "Assembly" : "Netmodule"}${flags & 2 ? "; embed interop types" : ""}` +
  `${flags & ~3 ? "; reserved flags present" : ""}`;

const customDataTable = (
  data: PortablePdbCustomData, pdb: PortablePdbInfo, id: string
): PagedSortableTableModel | null => {
  switch (data.type) {
    case "sourceLink": return textTable(id, data.documents, ["Source path pattern", "Source URL"],
      row => [row.pattern, row.url]);
    case "options": return textTable(id, data.options, ["Compilation option", "Value"],
      row => [row.name, row.value]);
    case "references": return textTable(id, data.references, ["Reference file", "Aliases", "Reference kind", "Image bytes"],
      row => [row.fileName, row.aliases || "(none)", referenceFlags(row.flags), String(row.fileSize)]);
    case "tupleNames": return textTable(id, data.names, ["Tuple element name"],
      name => [name || "(unnamed element)"]);
    case "typeDocuments": return textTable(id, data.documents, ["Type source document"],
      row => [pdb.documents[row - 1]?.name ?? "(unreadable document)"]);
    default: return null;
  }
};

const customSummary = (data: PortablePdbCustomData): string => {
  switch (data.type) {
    case "hoistedScopes": return `${data.scopes} scopes; ${data.inactiveScopes} inactive; summed IL length ${data.totalIlBytes} bytes`;
    case "dynamicFlags": return `${data.setBits} set flags in ${data.storedBits} stored bits`;
    case "encSlots": return `${data.slots} slots; ${data.temporaries} temporary; ${data.ordinalSlots} with ordinals`;
    case "encLambdas": return `${data.closures} closures; ${data.lambdas} lambdas`;
    case "encStates": return `${data.states} state entries`;
    case "asyncStepping": return `${data.awaits} awaits; catch handler ${data.hasCatchHandler ? "present" : "absent"}`;
    case "primaryConstructor": return "Primary constructor marker";
    default: return textSummary(data);
  }
};

const textSummary = (data: Extract<PortablePdbCustomData, { type:
  "sourceLink" | "options" | "references" | "tupleNames" | "defaultNamespace" | "typeDocuments" | "embeddedSource"
}>): string => {
  switch (data.type) {
    case "sourceLink": return `${data.documents.length} source path mappings`;
    case "options": return `${data.options.length} compilation options`;
    case "references": return `${data.references.length} compilation references`;
    case "tupleNames": return `${data.names.length} tuple elements`;
    case "defaultNamespace": return data.name || "(empty namespace)";
    case "typeDocuments": return `${data.documents.length} source document references`;
    case "embeddedSource": return sourceSummary(data.source);
  }
};

const sourceSummary = (source: PortablePdbSource | null): string => source
  ? `${source.bytes} source bytes; ${source.lines ?? "unknown"} lines; ${source.encoding ?? "unknown encoding"}; ${source.storage}`
  : "Embedded source was not decoded; see diagnostics";

const ownerNames = (pdb: PortablePdbInfo, metadata: PeClrMetadataTables | undefined): Map<string, string | null> => {
  const names = new Map<string, string | null>();
  pdb.documents.forEach((document, index) => names.set(`48:${index + 1}`, document.name));
  let variable = 0;
  let constant = 0;
  pdb.locals.forEach(local => names.set(local.kind === "variable" ? `51:${++variable}` : `52:${++constant}`, local.name));
  metadata?.methodDefs.forEach(method => names.set(`6:${method.row}`, method.name));
  metadata?.typeDefs.forEach(type => names.set(`2:${type.row}`, type.fullName));
  metadata?.modules.forEach(module => names.set(`0:${module.row}`, module.name));
  return names;
};

const customName = (record: PortablePdbCustomRecord): string =>
  PORTABLE_PDB_CUSTOM_KINDS[record.kind ?? ""]?.name ?? "Other custom debug information";

const summaryTable = (
  pdb: PortablePdbInfo, id: string, metadata: PeClrMetadataTables | undefined
): PagedSortableTableModel => {
  const names = ownerNames(pdb, metadata);
  const labels: Record<number, string> = { 0: "Module", 2: "Type", 6: "Method", 48: "Document", 51: "Local", 52: "Constant" };
  return textTable(id, pdb.customRecords, ["Custom debug information", "Owner", "Payload bytes", "Contents"], record => [
    customName(record), names.get(`${record.parent.tableId}:${record.parent.row}`) ??
      `${labels[record.parent.tableId] ?? "Metadata"} #${record.parent.row}`,
    String(record.size ?? "unknown"), record.data
      ? customSummary(record.data) : "Opaque or malformed custom record"
  ]);
};

const embeddedPdb = (pe: PeWindowsParseResult, index: number): PortablePdbInfo | undefined =>
  pe.debug?.entries?.[index]?.embeddedPortablePdb?.portablePdb;

export const getPortablePdbCustomTableModel = (
  pe: PeWindowsParseResult, tableId: string
): PagedSortableTableModel | null => {
  const match = /^pe-debug-entry-(\d+)-custom(?:-(\d+))?$/.exec(tableId);
  if (!match) return null;
  const pdb = embeddedPdb(pe, Number(match[1]));
  if (!pdb) return null;
  if (match[2] === undefined) return summaryTable(pdb, tableId, pe.clr?.meta?.tables);
  const data = pdb.customRecords[Number(match[2])]?.data;
  return data ? customDataTable(data, pdb, tableId) : null;
};

export const renderPortablePdbCustom = (
  pdb: PortablePdbInfo, out: string[], entryIndex: number, metadata?: PeClrMetadataTables
): void => {
  if (!pdb.customRecords.length) return;
  out.push(renderAutoPagedSortableTable(summaryTable(pdb, `pe-debug-entry-${entryIndex}-custom`, metadata)));
  pdb.customRecords.forEach((record, index) => {
    if (!record.data) return;
    const model = customDataTable(record.data, pdb, `pe-debug-entry-${entryIndex}-custom-${index}`);
    if (model?.rowCount) out.push(renderAutoPagedSortableTable(model));
  });
  out.push(`<p class="smallNote">Source Link URLs are metadata only and are never fetched. ` +
    `Scope lengths are sums, not unique code coverage.</p>`);
};
