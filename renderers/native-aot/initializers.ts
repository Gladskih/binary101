import { nativeAotSectionName, type NativeAotInitializerTable } from
  "../../analyzers/native-aot/format.js";
import { escapeHtml } from "../../html-utils.js";

export const renderNativeAotInitializers = (
  tables: NativeAotInitializerTable[] | undefined
): string => {
  if (!tables?.length) return "";
  return `<h4>NativeAOT initializer entry points</h4>` +
    `<p class="smallNote">Validated initializer targets supply seeds to the disassembler. ` +
    `Counts are unique within each table; other seed sources may identify the same code.</p>` +
    `<div class="tableWrap"><table class="table"><thead><tr><th>Source</th>` +
    `<th class="peNumeric">Entry points</th><th>Warnings</th></tr></thead><tbody>` +
    tables.map(table => `<tr><td>${escapeHtml(nativeAotSectionName(table.sectionType))}</td>` +
      `<td class="peNumeric">${table.targetRvas.length}</td>` +
      `<td>${table.warnings.map(escapeHtml).join("; ")}</td></tr>`).join("") +
    `</tbody></table></div>`;
};
