import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import type { PeClrHeader } from "../../analyzers/pe/clr/types.js";
import type { PeClrReadyToRun, PeClrReadyToRunImport, PeClrReadyToRunSection } from
  "../../analyzers/pe/clr/ready-to-run-types.js";
import { hex } from "../../binary-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from
  "../paged-sortable-table.js";

const model = (id: string, columns: string[], rows: (string | number)[][]):
PagedSortableTableModel => ({
  id, columns: columns.map(label => ({ label,
    className: label === "Name" || label === "Bytes" ? "" : "peNumeric" })),
  rowCount: rows.length, pageSize: 100,
  tableClassName: "readyToRunTable",
  rowAt: index => rows[index] ? { cells: rows[index]!.map((value, column) => ({
    html: value === "" ? "-" : escapeHtml(String(value)), sortValue: String(value),
    className: columns[column] === "Name" || columns[column] === "Bytes" ? "" : "peNumeric"
  })) } : null,
  sortValueAt: (row, column) => String(rows[row]?.[column] ?? "")
});

const importModels = (imports: PeClrReadyToRunImport[], id: string): PagedSortableTableModel[] => {
  return [model(`${id}-imports`,
    ["Index", "Cells RVA", "Size", "Flags", "Type", "Entry size", "Signatures RVA", "Auxiliary RVA"],
    imports.map((table, index) => [index, hex(table.rva, 8), table.size,
      hex(table.flags, 4), table.type, table.entrySize, hex(table.signaturesRva, 8),
      hex(table.auxiliaryDataRva, 8)])),
  model(`${id}-cells`, ["Import", "Cell", "RVA", "Bytes", "Signature RVA"],
    imports.flatMap((table, tableIndex) => table.entries.map((entry, index) => [
      tableIndex, index, hex(table.rva + index * entry.value.length, 8),
      [...entry.value].map(byte => byte.toString(16).padStart(2, "0")).join(" "),
      entry.signatureRva === null ? "" : hex(entry.signatureRva, 8)
    ])))];
};

const sectionModels = (
  section: PeClrReadyToRunSection, index: number
): PagedSortableTableModel[] => {
  const id = `pe-r2r-${index}`;
  const decoded = section.decoded;
  if (!decoded || decoded.kind === "text") return [];
  if (decoded.kind === "imports") return importModels(decoded.imports, id);
  if (decoded.kind === "methods") return [model(`${id}-methods`,
    ["MethodDef RID", "Runtime function index", "Fixups RVA"], decoded.methods.map(method =>
      [method.methodRid, method.runtimeFunctionIndex,
        method.fixupOffset === null ? "" : hex(section.rva + method.fixupOffset, 8)]))];
  if (decoded.kind === "hot-cold") return [model(`${id}-hot-cold`,
    ["Cold runtime function", "Hot runtime function"], decoded.entries.map(entry =>
      [entry.coldRuntimeFunction, entry.hotRuntimeFunction]))];
  return [model(`${id}-components`,
    ["CLR RVA", "CLR size", "Core header RVA", "Core header size"], decoded.entries.map(entry =>
      [hex(entry.clrRva, 8), entry.clrSize, hex(entry.coreHeaderRva, 8), entry.coreHeaderSize]))];
};

export const createReadyToRunTableModels = (data: PeClrReadyToRun): PagedSortableTableModel[] => [
  model("pe-r2r-sections", ["Type", "Name", "RVA", "Size"], data.sections.map(section =>
    [section.type, section.name, hex(section.rva, 8), section.size])),
  ...data.sections.flatMap(sectionModels)
];

export const getReadyToRunTableModel = (
  clr: PeClrHeader | null | undefined, id: string
): PagedSortableTableModel | null => id.startsWith("pe-r2r-") && clr?.readyToRun
  ? createReadyToRunTableModels(clr.readyToRun).find(model => model.id === id) ?? null : null;

export const renderReadyToRunData = (data: PeClrReadyToRun): string => {
  const text = data.sections.flatMap(section => section.decoded?.kind === "text"
    ? [renderDefinitionRow(section.name, escapeHtml(section.decoded.text),
      "Decoded ReadyToRun text section.")] : []).join("");
  return (text ? `<dl>${text}</dl>` : "") + createReadyToRunTableModels(data)
    .filter(table => table.rowCount).map(table => renderAutoPagedSortableTable(table)).join("");
};
