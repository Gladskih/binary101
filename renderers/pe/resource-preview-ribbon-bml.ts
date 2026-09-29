"use strict";

import type { ResourcePreviewData } from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtml } from "../../html-utils.js";

// Cap HTML output for deeply populated compiled ribbons.
const MAX_RENDERED_CONTROLS = 1000;

const renderControlTree = (
  root: NonNullable<ResourcePreviewData["ribbonBml"]>["tree"]
): string => {
  if (!root) return "";
  const rows: string[] = [];
  const stack = [{ control: root, level: 0 }];
  while (stack.length && rows.length < MAX_RENDERED_CONTROLS) {
    const item = stack.pop();
    if (!item) break;
    rows.push(`<tr><td class="peNumeric">${item.level}</td>` +
      `<td>${escapeHtml(item.control.kind)}</td>` +
      `<td class="peNumeric">${item.control.commandId ?? "–"}</td></tr>`);
    for (let index = item.control.children.length - 1; index >= 0; index -= 1) {
      const child = item.control.children[index];
      if (child) stack.push({ control: child, level: item.level + 1 });
    }
  }
  return `<h4>Control hierarchy</h4><div style="overflow-x:auto">` +
    `<table class="table peResourceNestedTable"><thead><tr><th>Level</th>` +
    `<th>Control</th><th>Command ID</th></tr></thead><tbody>` +
    rows.join("") + `</tbody></table></div>` +
    (stack.length ? `<p>Only the first ${MAX_RENDERED_CONTROLS} controls are shown.</p>` : "");
};

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
    `</tr></thead><tbody>${rows.join("")}</tbody></table></div>` +
    renderControlTree(ribbon.tree);
};
