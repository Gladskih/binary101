import type { NativeAotFunctionMap, NativeAotFunctionMaps } from "../../analyzers/native-aot/function-map-types.js";
import { nativeAotSectionName } from "../../analyzers/native-aot/format.js";
import { escapeHtml } from "../../html-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { createAnalysisStatisticsTable } from "../analysis-statistics.js";
import { nativeAotFunctionMapStatistics } from "./function-map-statistics.js";

const fieldModel = (map: Extract<NativeAotFunctionMap, { type: 316 }>): PagedSortableTableModel => {
  const fields = map.entries.flatMap(entry => entry.fields.map(field => ({ typeIndex: entry.typeIndex, ...field })));
  return { id: "native-aot-function-map-316-fields", rowCount: fields.length, pageSize: 100,
    columns: [{ label: "Type record", className: "peNumeric" }, { label: "Native field" },
      { label: "Byte offset", className: "peNumeric" }],
    rowAt: index => {
      const field = fields[index];
      return field ? { cells: [
        { html: String(field.typeIndex), sortValue: String(field.typeIndex), className: "peNumeric" },
        { html: escapeHtml(field.name), sortValue: field.name },
        { html: String(field.offset), sortValue: String(field.offset), className: "peNumeric" }
      ] } : null;
    },
    sortValueAt: (row, column) => {
      const field = fields[row];
      return field ? String([field.typeIndex, field.name, field.offset][column] ?? "") : "";
    }
  };
};

const mapModels = (map: NativeAotFunctionMap): PagedSortableTableModel[] => [
  createAnalysisStatisticsTable(`native-aot-function-map-${map.type}`, nativeAotFunctionMapStatistics(map)),
  ...(map.type === 316 ? [fieldModel(map)] : [])
];

export const getNativeAotFunctionTableModel = (
  data: NativeAotFunctionMaps | undefined, id: string
): PagedSortableTableModel | null => id.startsWith("native-aot-function-map-")
  ? data?.maps.flatMap(mapModels).find(table => table.id === id) ?? null : null;

const warnings = (values: string[]) => values.length
  ? `<ul class="smallNote">${values.map(value => `<li>${escapeHtml(value)}</li>`).join("")}</ul>` : "";

export const renderNativeAotFunctionMaps = (data: NativeAotFunctionMaps | undefined): string => {
  if (!data) return "";
  return `<h4>NativeAOT runtime relationships</h4><p class="smallNote">These maps connect types, ` +
    `generic code and native interop. Validated method addresses supply disassembly seeds. ` +
    `Counts describe each map separately; the same code may appear in several sources.</p>` +
    warnings(data.warnings) + data.maps.map(map => `<h5>${escapeHtml(nativeAotSectionName(map.type))}</h5>` +
      warnings(map.warnings) + mapModels(map).filter(table => table.rowCount)
        .map(table => renderAutoPagedSortableTable(table)).join("")).join("");
};
