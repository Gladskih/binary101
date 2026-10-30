import type { WasmParseResult } from "../../analyzers/wasm/types.js";
import { escapeHtmlText, renderDefinitionRow } from "../../html-utils.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import { getWasmPagedTableModel } from "./paged-tables.js";

export const renderWasm = (data: WasmParseResult): string => {
  const tables = ["Sections", "Types", "Imports", "Exports", "Functions", "Memories", "Tables",
    "Globals", "Elements", "Data", "Tags", "Producers", "Features"];
  return `<h3>WebAssembly module</h3><dl>` +
    renderDefinitionRow("Binary version", escapeHtmlText(String(data.version ?? "Unknown"))) +
    renderDefinitionRow("Module name", escapeHtmlText(data.moduleName ?? "—")) +
    renderDefinitionRow("File bytes", String(data.fileSize)) +
    renderDefinitionRow("Start function", escapeHtmlText(String(data.start ?? "None"))) +
    renderDefinitionRow("Declared data count", escapeHtmlText(String(data.dataCount ?? "Not declared"))) +
    `</dl><p>Structural analysis; the module is not executed. Full semantic validation is not performed.</p>` +
    (data.issues.length ? `<h4>Issues</h4><ul class="issueList">` +
      data.issues.map(issue => `<li>${escapeHtmlText(issue)}</li>`).join("") + `</ul>` : "") +
    tables.map(title => {
      const model = getWasmPagedTableModel(data, `wasm-${title.toLowerCase()}`)!;
      return model.rowCount ? `<h4>${title}</h4>${renderAutoPagedSortableTable(model)}` : "";
    }).join("") +
    `<p>Memory limits use WebAssembly pages (65536 bytes). Defined table, memory, global and tag ` +
    `indices are relative to their defined entries; imports precede them in each index space.</p>`;
};
