import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import type { PeClrHeader } from "../../analyzers/pe/clr/types.js";
import type { PeClrReadyToRun, PeClrReadyToRunComponent, PeClrReadyToRunImport, PeClrReadyToRunSection } from
  "../../analyzers/pe/clr/ready-to-run-types.js";
import { hex } from "../../binary-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from
  "../paged-sortable-table.js";

const columnClass = (label: string | undefined): string =>
  ["Name", "Bytes", "Kind"].includes(label ?? "") ? "" : "peNumeric";

const model = (id: string, columns: string[], rows: (string | number)[][]):
PagedSortableTableModel => ({
  id, columns: columns.map(label => ({ label,
    className: columnClass(label) })),
  rowCount: rows.length, pageSize: 100,
  tableClassName: "readyToRunTable",
  rowAt: index => rows[index] ? { cells: rows[index]!.map((value, column) => ({
    html: value === "" ? "-" : escapeHtml(String(value)), sortValue: String(value),
    className: columnClass(columns[column])
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
  section: PeClrReadyToRunSection, index: number, prefix = "pe-r2r"
): PagedSortableTableModel[] => {
  const id = `${prefix}-${index}`;
  const decoded = section.decoded;
  if (!decoded || decoded.kind === "text") return [];
  if (decoded.kind === "thunks") return [model(`${id}-thunks`,
    ["RVA", "Size", "Kind", "Helper cell RVA", "Module cell RVA", "Import section"],
    decoded.entries.map(entry => [hex(entry.rva, 8), entry.size, entry.kind,
      entry.helperCellRva === null ? "" : hex(entry.helperCellRva, 8),
      entry.moduleCellRva == null ? "" : hex(entry.moduleCellRva, 8), entry.importSectionIndex ?? ""]))];
  if (decoded.kind === "imports") return importModels(decoded.imports, id);
  if (decoded.kind === "methods") return [model(`${id}-methods`,
    ["MethodDef RID", "Runtime function index", "Fixups RVA"], decoded.methods.map(method =>
      [method.methodRid, method.runtimeFunctionIndex,
        method.fixupOffset === null ? "" : hex(section.rva + method.fixupOffset, 8)]))];
  if (decoded.kind === "instance-methods") return [model(`${id}-instance-methods`,
    ["Signature RVA", "Runtime function index", "Fixups RVA"], decoded.methods.map(method =>
      [hex(section.rva + method.signatureOffset, 8), method.runtimeFunctionIndex,
        method.fixupOffset === null ? "" : hex(section.rva + method.fixupOffset, 8)]))];
  if (decoded.kind === "hot-cold") return [model(`${id}-hot-cold`,
    ["Cold runtime function", "Hot runtime function"], decoded.entries.map(entry =>
      [entry.coldRuntimeFunction, entry.hotRuntimeFunction]))];
  return componentModels(decoded.entries, id);
};

const componentModels = (entries: PeClrReadyToRunComponent[], id: string):
PagedSortableTableModel[] => [model(`${id}-components`,
    ["CLR RVA", "CLR size", "Core header RVA", "Core header size", "Flags", "Sections"],
    entries.map(entry => [hex(entry.clrRva, 8), entry.clrSize, hex(entry.coreHeaderRva, 8),
      entry.coreHeaderSize, entry.coreHeader ? hex(entry.coreHeader.flags, 8) : "",
      entry.coreHeader?.sectionCount ?? ""])),
  ...entries.flatMap((entry, component) => entry.coreHeader ? [
    model(`${id}-component-${component}-sections`, ["Type", "Name", "RVA", "Size"],
      entry.coreHeader.sections.map(section => [section.type, section.name, hex(section.rva, 8), section.size])),
    ...entry.coreHeader.sections.flatMap((section, child) => sectionModels(section, child,
      `${id}-component-${component}`))
  ] : [])];

export const createReadyToRunTableModels = (data: PeClrReadyToRun): PagedSortableTableModel[] => [
  model("pe-r2r-sections", ["Type", "Name", "RVA", "Size"], data.sections.map(section =>
    [section.type, section.name, hex(section.rva, 8), section.size])),
  ...data.sections.flatMap((section, index) => sectionModels(section, index))
];

export const getReadyToRunTableModel = (
  clr: Pick<PeClrHeader, "readyToRun"> | null | undefined, id: string
): PagedSortableTableModel | null => id.startsWith("pe-r2r-") && clr?.readyToRun
  ? createReadyToRunTableModels(clr.readyToRun).find(model => model.id === id) ?? null : null;

export const renderReadyToRunData = (data: PeClrReadyToRun): string => {
  const text = data.sections.flatMap(section => section.decoded?.kind === "text"
    ? [renderDefinitionRow(section.name, escapeHtml(section.decoded.text),
      "Decoded ReadyToRun text section.")] : []).join("");
  return (text ? `<dl>${text}</dl>` : "") + createReadyToRunTableModels(data)
    .filter(table => table.rowCount).map(table => {
      const component = /-component-(\d+)-sections$/.exec(table.id);
      return (component ? `<h5>Component assembly ${Number(component[1]) + 1}</h5>` : "") +
        renderAutoPagedSortableTable(table);
    }).join("");
};
