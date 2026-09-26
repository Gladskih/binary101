import type { DModuleInfo } from "../../analyzers/d-runtime/types.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import { escapeHtml } from "../../html-utils.js";
import {
  renderAutoPagedSortableTable, type PagedSortableTableModel
} from "../paged-sortable-table.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import { createDRuntimeReferenceTableModel } from "./d-runtime-references.js";

export const D_MODULE_TABLE_ID = "pe-d-runtime-modules";

const hex = (value: bigint | number): string => `0x${value.toString(16)}`;

const moduleValues = (module: DModuleInfo): string[] => [
  module.name, module.address.toString(), String(module.flags), String(module.index),
  String(module.importedModules.length), String(module.localClasses.length),
  module.callbacks.map(callback => `${callback.kind} ${hex(callback.address)}`).join("; ")
];

const moduleCellHtml = (module: DModuleInfo, column: number): string => {
  if (column === 0) return escapeHtml(module.name);
  if (column === 1) return hex(module.address);
  if (column === 2) return hex(module.flags);
  if (column === 3) return String(module.index);
  if (column === 4) return String(module.importedModules.length);
  if (column === 5) return String(module.localClasses.length);
  return module.callbacks.map(callback => `${escapeHtml(callback.kind)} ${hex(callback.address)}`)
    .join("<br>");
};

export const createDRuntimeModuleTableModel = (modules: DModuleInfo[]): PagedSortableTableModel => {
  const columns = [
    { label: "Module" }, { label: "ModuleInfo VA", className: "peNumeric" },
    { label: "Flags", className: "peNumeric" }, { label: "Index", className: "peNumeric" },
    { label: "Imports", className: "peNumeric" },
    { label: "Local classes", className: "peNumeric" },
    { label: "Callbacks (VA)" }
  ];
  return {
    id: D_MODULE_TABLE_ID,
    pageSize: 250, // Match existing PE table pagination; UI policy, not an ABI limit.
    rowCount: modules.length,
    columns,
    rowAt: index => {
      const module = modules[index];
      if (!module) return null;
      return { cells: moduleValues(module).map((sortValue, column) => ({
        html: moduleCellHtml(module, column), sortValue,
        ...(columns[column]!.className ? { className: columns[column]!.className } : {})
      })) };
    },
    sortValueAt: (index, column) => {
      const module = modules[index];
      return module ? moduleValues(module)[column] ?? "" : "";
    }
  };
};

export const renderDRuntime = (pe: PeWindowsParseResult, out: string[]): void => {
  const runtime = pe.dRuntime;
  if (!runtime) return;
  out.push(renderPeSectionStart("D runtime metadata", `${runtime.modules.length} validated modules`));
  for (const warning of runtime.warnings) out.push(`<p class="smallNote">${escapeHtml(warning)}</p>`);
  if (runtime.modules.length) {
    out.push(renderAutoPagedSortableTable(createDRuntimeModuleTableModel(runtime.modules)));
    const references = createDRuntimeReferenceTableModel(runtime.modules);
    if (references.rowCount) out.push(renderAutoPagedSortableTable(references));
  }
  out.push(renderPeSectionEnd());
};
