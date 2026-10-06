import type { NativeAotFunctionMap, NativeAotFunctionMaps } from "../../analyzers/native-aot/function-map-types.js";
import { nativeAotSectionName } from "../../analyzers/native-aot/format.js";
import { escapeHtml } from "../../html-utils.js";
import { hex } from "../../binary-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";

type CellValue = string | number;
const address = (value: number | null): string => value === null ? "-" : hex(value, 8);
const model = (id: string, labels: string[], rowCount: number,
  cellsAt: (index: number) => CellValue[] | null): PagedSortableTableModel => ({
  id, rowCount, pageSize: 100,
  columns: labels.map(label => ({ label, className: label === "Name" ? "" : "peNumeric" })),
  rowAt: index => {
    const cells = cellsAt(index);
    return cells ? { cells: cells.map((value, column) => ({
      html: escapeHtml(String(value)), sortValue: String(value),
      className: labels[column] === "Name" ? "" : "peNumeric"
    })) } : null;
  },
  sortValueAt: (row, column) => String(cellsAt(row)?.[column] ?? "")
});

const structModels = (map: Extract<NativeAotFunctionMap, { type: 316 }>, id: string) => {
  const fields = map.entries.flatMap(entry => entry.fields.map(field => ({ typeIndex: entry.typeIndex, ...field })));
  return [model(id, ["Type index", "Header", "Native size", "Marshal RVA", "Unmarshal RVA", "Cleanup RVA"],
    map.entries.length, index => {
      const entry = map.entries[index];
      return entry ? [entry.typeIndex, hex(entry.header, 8), entry.nativeSize ?? "-",
        address(entry.marshalRva), address(entry.unmarshalRva), address(entry.cleanupRva)] : null;
    }), model(`${id}-fields`, ["Type index", "Name", "Offset"], fields.length, index => {
    const field = fields[index];
    return field ? [field.typeIndex, field.name, field.offset] : null;
  })];
};

const mapModels = (map: NativeAotFunctionMap): PagedSortableTableModel[] => {
  const id = `native-aot-function-map-${map.type}`;
  if (map.type === 310) return [model(id, ["Type index", "Static base index", "Entry point RVA"],
    map.entries.length, index => {
      const entry = map.entries[index];
      return entry ? [entry.typeIndex, entry.staticBaseIndex, address(entry.entrypointRva)] : null;
    })];
  if (map.type === 316) return structModels(map, id);
  if (map.type === 317) return [model(id, ["Type index", "Open static RVA", "Closed RVA", "Forward creation RVA"],
    map.entries.length, index => {
      const entry = map.entries[index];
      return entry ? [entry.typeIndex, address(entry.openStaticRva), address(entry.closedRva),
        address(entry.forwardCreationRva)] : null;
    })];
  if (map.type === 336) return [model(id, ["Type index", "Method token", "Generic type indices", "Entry point RVA"],
    map.entries.length, index => {
      const entry = map.entries[index];
      return entry ? [entry.declaringTypeIndex, hex(entry.methodToken, 8),
        entry.genericArgumentIndices.join(", ") || "-", address(entry.entrypointRva)] : null;
    })];
  if (map.type === 321) return [model(id, ["Type index", "Layout offset", "Class constructor RVA"],
    map.entries.length, index => {
      const entry = map.entries[index];
      return entry ? [entry.typeIndex, hex(entry.layoutOffset, 8), address(entry.layout.classConstructorRva)] : null;
    }), ...dictionaryModels(map, id)];
  return [model(id, ["Signature offset", "Layout offset", "Flags", "Type index", "Method token",
    "Generic type indices", "Entry point RVA"], map.entries.length, index => {
    const entry = map.entries[index];
    return entry ? [hex(entry.signatureOffset, 8), hex(entry.layoutOffset, 8), hex(entry.flags, 2),
      entry.declaringTypeIndex, hex(entry.methodToken, 8), entry.genericArgumentIndices.join(", ") || "-",
      address(entry.entrypointRva)] : null;
  }), ...dictionaryModels(map, id)];
};

const dictionaryModels = (map: Extract<NativeAotFunctionMap, { type: 321 | 322 }>, id: string) => {
  const methods = map.entries.flatMap(entry => entry.layout?.dictionaryMethods ?? []);
  return [model(`${id}-dictionary`, ["Signature offset", "Flags", "Method token", "Entry point RVA"],
    methods.length, index => {
      const entry = methods[index];
      return entry ? [hex(entry.signatureOffset, 8), hex(entry.flags, 2),
        hex(entry.methodToken, 8), address(entry.entrypointRva)] : null;
    })];
};

export const getNativeAotFunctionTableModel = (
  data: NativeAotFunctionMaps | undefined, id: string
): PagedSortableTableModel | null => id.startsWith("native-aot-function-map-")
  ? data?.maps.flatMap(mapModels).find(table => table.id === id) ?? null : null;

const warnings = (values: string[]) => values.length
  ? `<ul class="smallNote">${values.map(value => `<li>${escapeHtml(value)}</li>`).join("")}</ul>` : "";

export const renderNativeAotFunctionMaps = (data: NativeAotFunctionMaps | undefined): string => {
  if (!data) return "";
  return `<h4>NativeAOT function maps</h4><p class="smallNote">Validated thunk and method addresses ` +
    `supply disassembly seeds. Type indices and method tokens refer to retained metadata.</p>` +
    warnings(data.warnings) + data.maps.map(map => `<h5>${escapeHtml(nativeAotSectionName(map.type))}</h5>` +
      warnings(map.warnings) + mapModels(map).filter(table => table.rowCount)
        .map(table => renderAutoPagedSortableTable(table)).join("")).join("");
};
