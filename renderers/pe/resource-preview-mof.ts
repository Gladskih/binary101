"use strict";

import type { ResourcePreviewData } from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtml } from "../../html-utils.js";

export const renderBinaryMofPreview = (
  mof: NonNullable<ResourcePreviewData["binaryMof"]>
): string => `<p>Binary WMI MOF: ${mof.classes.length} classes, ` +
  `${mof.flavorCount} qualifier flavors.</p>` +
  `<div style="overflow-x:auto"><table class="table peResourceNestedTable"><thead><tr>` +
  `<th>Class</th><th>GUID</th><th>Namespace</th><th>Base class</th>` +
  `<th>Properties</th><th>Methods</th>` +
  `</tr></thead><tbody>` + mof.classes.map(item =>
    `<tr><td class="mono">${escapeHtml(item.name ?? "–")}</td>` +
    `<td class="mono">${escapeHtml(item.guid ?? "–")}</td>` +
    `<td class="mono">${escapeHtml(item.namespace ?? "–")}</td>` +
    `<td class="mono">${escapeHtml(item.superclass ?? "–")}</td>` +
    `<td>${escapeHtml(item.properties.map(property =>
      `${property.name}: ${property.type}`).join(", ") || "–")}</td>` +
    `<td>${escapeHtml(item.methods.join(", ") || "–")}</td></tr>`).join("") +
  `</tbody></table></div>`;
