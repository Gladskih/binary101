import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { sframeFunctionAddress, SFRAME_START_PCREL } from "../../analyzers/elf/sframe-layout.js";
import type { ElfSFrame, ElfSFrameFunction, ElfSFrameRow } from
  "../../analyzers/elf/sframe-types.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";
import { SFRAME_ABI, sframeRules } from "./sframe-rules.js";
import { formatElfHex } from "./value-format.js";

export const elfSFrameTitle = ({ source }: ElfSFrame): string => "sectionIndex" in source
  ? `SFrame (section #${source.sectionIndex})`
  : `SFrame (PT_GNU_SFRAME #${source.programHeaderIndex})`;

const abiNames: Readonly<Record<number, string>> = {
  [SFRAME_ABI.AARCH64_BE]: "AArch64 big-endian", [SFRAME_ABI.AARCH64_LE]: "AArch64 little-endian",
  [SFRAME_ABI.AMD64]: "AMD64 little-endian", [SFRAME_ABI.S390X]: "s390x big-endian"
};

const formatFlags = (version: number, flags: number): string => {
  if (version < 1 || version > 3) return formatElfHex(flags);
  const flagNames = [(flags & 1) && "Sorted FDEs",
    version !== 3 && (flags & 2) && "Frame pointers preserved",
    version !== 1 && (flags & SFRAME_START_PCREL) && "PC-relative FDEs"]
    .filter(Boolean);
  return [formatElfHex(flags), ...flagNames].join(" · ");
};

const renderHeader = (table: ElfSFrame): string => {
  const { preamble, header } = table;
  if (!preamble) return "";
  const fields: [string, string | number][] = [
    ["Version", preamble.version], ["Flags", formatFlags(preamble.version, preamble.flags)]
  ];
  if (header) fields.push(
    ["ABI", abiNames[header.abi] ?? `Unknown (${header.abi})`],
    ["Fixed frame pointer offset from CFA", header.fixedFpOffset || "—"],
    ["Fixed return address offset from CFA", header.fixedRaOffset || "—"],
    ["Function descriptors declared", header.functionCount],
    ["Frame rows declared", header.rowCount]
  );
  return "<dl>" +
    fields.map(([label, value]) => renderDefinitionRow(label, String(value))).join("") + "</dl>";
};

const functionStart = (table: ElfSFrame, entry: ElfSFrameFunction): string => {
  const address = sframeFunctionAddress(table, entry);
  return address == null ? "—" : formatElfHex(address);
};

const functionFormat = (entry: ElfSFrameFunction, version: number): string => {
  const { attributes } = entry;
  if (!attributes) return "—";
  const kind = (attributes.info2 ?? 0) & 31;
  const mode = attributes.info & 16
    ? attributes.repeatSize ? `Repeating PC (${attributes.repeatSize} bytes)` : "Repeating PC"
    : "Increasing PC";
  return [kind === 0 ? "Default" : kind === 1 ? "Flexible" : `Type ${kind}`, mode,
    version === 3 && attributes.info & 128 ? "Signal frame" : ""].filter(Boolean).join(" · ");
};

const functionValues = (table: ElfSFrame, entry: ElfSFrameFunction, index: number): string[] => [
  String(index), formatElfHex(entry.offset), functionStart(table, entry), String(entry.startOffset),
  String(entry.size), String(entry.attributes?.rowCount ?? "—"),
  functionFormat(entry, table.preamble!.version), entry.issues.join(" · ")
];

const rowValues = (table: ElfSFrame, row: ElfSFrameRow): string[] => {
  const { attributes } = table.functions[row.functionIndex]!;
  const { abi } = table.header!;
  const signed = (abi === SFRAME_ABI.AARCH64_BE || abi === SFRAME_ABI.AARCH64_LE) && row.info & 128;
  return [String(row.functionIndex), String(row.pcOffset),
    ...sframeRules(row, table.header!, table.preamble!.version, (attributes?.info2 ?? 0) & 31),
    signed ? (attributes!.info & 32 ? "Key B" : "Key A") : "—",
    row.words.join(", ") || "—"];
};

const tableModel = (id: string, rowCount: number,
  columns: PagedSortableTableModel["columns"], numericColumns: number,
  values: (index: number) => string[]
): PagedSortableTableModel => {
  const className = (column: number): string => column < numericColumns ? "peNumeric" : "";
  return { id, rowCount, pageSize: 100,
    columns: columns.map((header, column) => ({ ...header, className: className(column) })),
    rowAt: index => index < 0 || index >= rowCount ? null : { cells: values(index).map(
      (value, column) => ({ html: escapeHtml(value), sortValue: value, className: className(column) })) },
    sortValueAt: (index, column) =>
      index < 0 || index >= rowCount ? "" : values(index)[column] ?? ""
  };
};

const functionTable = (table: ElfSFrame, index: number): PagedSortableTableModel =>
  tableModel(`elf-sframe-functions-${index}`, table.functions.length,
    [{ label: "FDE" }, { label: "Offset", tooltip: "FDE offset within SFrame" },
      { label: "Function PC" }, { label: "PC delta", tooltip: "Encoded function start offset" },
      { label: "Bytes", tooltip: "Function size in bytes" }, { label: "Frame rows" },
      { label: "Encoding" }, { label: "Notices" }], 6,
    row => functionValues(table, table.functions[row]!, row));

const rowTable = (table: ElfSFrame, index: number): PagedSortableTableModel =>
  tableModel(`elf-sframe-rows-${index}`, table.rows.length,
    [{ label: "FDE" }, { label: "PC offset", tooltip: "Encoded PC offset in the frame row entry" },
      { label: "CFA", tooltip: "Canonical frame address" },
      { label: "FP", tooltip: "Frame pointer" }, { label: "RA", tooltip: "Return address" },
      { label: "RA signing" }, { label: "Encoded words" }], 2,
    row => rowValues(table, table.rows[row]!));

export const getElfSFrameTableModel = (elf: ElfParseResult, id: string): PagedSortableTableModel | null => {
  for (const [index, table] of (elf.sframe ?? []).entries()) {
    if (id === `elf-sframe-functions-${index}`) return functionTable(table, index);
    if (id === `elf-sframe-rows-${index}`) return rowTable(table, index);
  }
  return null;
};

const renderTable = (table: ElfSFrame, index: number, out: string[]): void => {
  out.push(renderElfSectionStart(elfSFrameTitle(table)), renderHeader(table));
  if (table.address == null && table.functions.length) {
    out.push('<p class="smallNote">Function PCs in relocatable objects require relocation.</p>');
  }
  if (table.issues.length) out.push(
    `<ul>${table.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`);
  if (table.functions.length) out.push("<h4>Function descriptors</h4>",
    renderAutoPagedSortableTable(functionTable(table, index)));
  if (table.rows.length) out.push("<h4>Frame rows</h4>",
    renderAutoPagedSortableTable(rowTable(table, index)));
  out.push(renderElfSectionEnd());
};

export const renderElfSFrame = (elf: ElfParseResult, out: string[], onlyIndex?: number): void => {
  for (const [index, table] of (elf.sframe ?? []).entries()) {
    if (onlyIndex == null || index === onlyIndex) renderTable(table, index, out);
  }
};
