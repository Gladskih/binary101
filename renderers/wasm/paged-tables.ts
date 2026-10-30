import type { WasmParseResult } from "../../analyzers/wasm/types.js";
import { escapeHtmlText } from "../../html-utils.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import type { PagedSortableTableModel } from "../../ui/paged-sortable-table-state.js";
import { SECTION_NAMES, formatDescriptor, formatExpression, formatLimits, formatSignature } from "./format.js";

type CellValue = string | number | bigint | null;

const createTable = <Value>(id: string, columns: string[], rows: readonly Value[],
  cells: (row: Value, index: number) => CellValue[]): PagedSortableTableModel => ({
  id, rowCount: rows.length, pageSize: 50, tableClassName: "wasmTable",
  columns: columns.map(label => ({ label })),
  rowAt: index => {
    const row = rows[index];
    return row === undefined ? null : { cells: cells(row, index).map(value => ({
      html: escapeHtmlText(String(value ?? "—")),
      ...(typeof value === "number" || typeof value === "bigint" ? { className: "wasmTable__number" } : {})
    })) };
  },
  sortValueAt: (index, column) => {
    const row = rows[index];
    return row === undefined ? "" : String(cells(row, index)[column] ?? "");
  }
});

const instructionTable = (data: WasmParseResult, id: string): PagedSortableTableModel | null => {
  const match = /^wasm-code-(\d+)$/.exec(id);
  const code = match ? data.code[Number(match[1])] : undefined;
  return code ? createTable(id, ["File offset", "Instruction", "Operands"], code.instructions,
    row => [row.offset, row.mnemonic, row.operands]) : null;
};

const functionTable = (data: WasmParseResult, id: string): PagedSortableTableModel => {
  const imported = data.imports.filter(entry => entry.descriptor.kind === "function").length;
  const model = createTable(id, ["Index", "Name", "Type", "Signature", "Body bytes", "Local groups"],
    data.functions, (row, index) => [index + imported, data.functionNames[index + imported] ?? "",
      row.typeIndex, formatSignature(data.types[row.typeIndex]), data.code[index]?.size ?? null,
      data.code[index]?.locals.map(local => `${local.count} × ${local.type}`).join(", ") ?? ""]);
  return { ...model, rowAt: index => {
    const row = model.rowAt(index);
    const code = instructionTable(data, `wasm-code-${index}`);
    if (!row || !code?.rowCount) return row;
    return { ...row, additionalRowsHtml: `<tr><td colspan="6"><details>` +
      `<summary>Instructions (${code.rowCount})</summary>${renderAutoPagedSortableTable(code)}` +
      `</details></td></tr>` };
  } };
};

export const getWasmPagedTableModel = (data: WasmParseResult,
  id: string): PagedSortableTableModel | null => {
  switch (id) {
    case "wasm-sections": return createTable(id, ["Section", "ID", "Offset", "Payload offset", "Bytes", "Custom name", "Analysis"],
      data.sections, row => [SECTION_NAMES[row.id] ?? "Unknown", row.id, row.offset,
        row.payloadOffset, row.size, row.customName ?? "", row.status]);
    case "wasm-types": return createTable(id, ["Index", "Signature"], data.types,
      (row, index) => [index, formatSignature(row)]);
    case "wasm-imports": return createTable(id, ["Module", "Name", "Kind", "Descriptor"], data.imports,
      row => [row.module, row.name, row.descriptor.kind, formatDescriptor(row.descriptor)]);
    case "wasm-exports": return createTable(id, ["Name", "Kind", "Index"], data.exports,
      row => [row.name, row.kind, row.index]);
    case "wasm-functions": return functionTable(data, id);
    default: return storageTable(data, id);
  }
};

const storageTable = (data: WasmParseResult, id: string): PagedSortableTableModel | null => {
  switch (id) {
    case "wasm-memories": return createTable(id, ["Index (defined)", "Minimum pages", "Maximum pages", "Address width", "Shared"],
      data.memories, (row, index) => [index, row.min, row.max, row.address64 ? 64 : 32, String(row.shared)]);
    case "wasm-tables": return createTable(id, ["Index (defined)", "Element type", "Limits"], data.tables,
      (row, index) => [index, row.type, formatLimits(row.limits)]);
    case "wasm-globals": return createTable(id, ["Index (defined)", "Type", "Mutable", "Initializer"], data.globals,
      (row, index) => [index, row.descriptor.type, String(row.descriptor.mutable), formatExpression(row.expression)]);
    case "wasm-data": return createTable(id, ["Index", "Mode", "Memory", "Initializer", "File offset", "Bytes", "Byte preview"],
      data.data, (row, index) => [index, row.mode, row.memory, formatExpression(row.expression),
        row.offset, row.size, row.preview.map(byte => byte.toString(16).padStart(2, "0")).join(" ")]);
    case "wasm-elements": return createTable(id, ["Index", "Mode", "Table", "Offset expression", "Type", "Entries"],
      data.elements, (row, index) => [index, row.mode, row.table, formatExpression(row.expression), row.type,
        row.entries.map(entry => typeof entry === "number" ? String(entry) : formatExpression(entry)).join("; ")]);
    default: return metadataTable(data, id);
  }
};

const metadataTable = (data: WasmParseResult, id: string): PagedSortableTableModel | null => {
  switch (id) {
    case "wasm-producers": return createTable(id, ["Field", "Name", "Version"], data.producers,
      row => [row.field, row.name, row.version]);
    case "wasm-features": return createTable(id, ["Policy", "Feature"], data.features,
      row => [row.prefix, row.name]);
    case "wasm-tags": return createTable(id, ["Index (defined)", "Type"], data.tags,
      (row, index) => [index, row]);
    default: return instructionTable(data, id);
  }
};
