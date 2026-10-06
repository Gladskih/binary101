import type { NativeAotFunctionMap, NativeAotFunctionMaps } from "../../analyzers/native-aot/function-map-types.js";
import { nativeAotSectionName } from "../../analyzers/native-aot/format.js";
import { escapeHtml } from "../../html-utils.js";
import { hex } from "../../binary-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import type { NativeAotRuntimeType } from "../../analyzers/native-aot/runtime-type-map.js";

type CellValue = string | number;
const address = (value: number | null): string => value === null ? "-" : hex(value, 8);
const model = (id: string, labels: string[], rowCount: number,
  cellsAt: (index: number) => CellValue[] | null): PagedSortableTableModel => ({
  id, rowCount, pageSize: 100,
  columns: labels.map(label => ({ label, className: ["Name", "Kind"].includes(label) ? "" : "peNumeric" })),
  rowAt: index => {
    const cells = cellsAt(index);
    return cells ? { cells: cells.map((value, column) => ({
      html: escapeHtml(String(value)), sortValue: String(value),
      className: ["Name", "Kind"].includes(labels[column]!) ? "" : "peNumeric"
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

const mapModels = (map: Exclude<NativeAotFunctionMap, { type: 301 }>): PagedSortableTableModel[] => {
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

const typeModels = (map: Extract<NativeAotFunctionMap, { type: 301 }>): PagedSortableTableModel[] => {
  const slots = map.entries.flatMap(entry => (entry.runtimeType?.slots ?? []).map((slot, index) =>
    [entry.typeIndex, index, slot.kind, slot.kind === "null" ? "-" : address(slot.rva)]));
  return [model("native-aot-function-map-301",
    ["Type index", "Metadata handle", "MethodTable RVA", "Flags", "Base size", "Vtable slots", "Interfaces", "Hash"],
    map.entries.length, index => {
      const entry = map.entries[index];
      if (!entry) return null;
      return [entry.typeIndex, hex(entry.metadataHandle, 8), ...typeFields(entry.runtimeType)];
    }), model("native-aot-function-map-301-slots", ["Type index", "Slot", "Kind", "Target RVA"],
    slots.length, index => slots[index] ?? null)];
};

const typeFields = (type: NativeAotRuntimeType | null): CellValue[] => type ?
  [address(type.rva), hex(type.flags, 8), type.baseSize, type.numVtableSlots,
    type.numInterfaces, hex(type.hashCode, 8)] : Array<string>(6).fill("-");

const allMapModels = (map: NativeAotFunctionMap): PagedSortableTableModel[] =>
  map.type === 301 ? typeModels(map) : mapModels(map);

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
  ? data?.maps.flatMap(allMapModels).find(table => table.id === id) ?? null : null;

const warnings = (values: string[]) => values.length
  ? `<ul class="smallNote">${values.map(value => `<li>${escapeHtml(value)}</li>`).join("")}</ul>` : "";

export const renderNativeAotFunctionMaps = (data: NativeAotFunctionMaps | undefined): string => {
  if (!data) return "";
  return `<h4>NativeAOT function maps</h4><p class="smallNote">Validated thunk and method addresses ` +
    `supply disassembly seeds. Type indices and method tokens refer to retained metadata.</p>` +
    warnings(data.warnings) + data.maps.map(map => `<h5>${escapeHtml(nativeAotSectionName(map.type))}</h5>` +
      warnings(map.warnings) + allMapModels(map).filter(table => table.rowCount)
        .map(table => renderAutoPagedSortableTable(table)).join("")).join("");
};
