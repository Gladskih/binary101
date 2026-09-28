"use strict";

import type { ResourcePreviewData } from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtml } from "../../html-utils.js";

export const renderRibbonBmlPreview = (
  ribbon: NonNullable<ResourcePreviewData["ribbonBml"]>
): string => {
  const rows = ribbon.commands.flatMap(command =>
    (command.resources.length ? command.resources : [null]).map(resource =>
      `<tr><td class="peNumeric">${command.id}</td>` +
      `<td>${resource ? escapeHtml(resource.kind) : "–"}</td>` +
      `<td class="peNumeric">${resource?.resourceId ?? "–"}</td>` +
      `<td class="peNumeric">${resource?.minimumDpi ?? "–"}</td></tr>`));
  return `<p>Compiled Windows Ribbon: ${ribbon.commands.length} commands, ` +
    `${ribbon.strings.length} internal strings.</p>` +
    (ribbon.strings.length ? `<p class="smallNote">Internal strings: ` +
      escapeHtml(ribbon.strings.join(", ")) + `</p>` : "") +
    `<div style="overflow-x:auto"><table class="table peResourceNestedTable"><thead><tr>` +
    `<th>Command ID</th><th>Resource</th><th>Resource ID</th><th>Min DPI</th>` +
    `</tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
};
