"use strict";

import type { ResourcePreviewData } from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtml } from "../../html-utils.js";
import { resolvedPreview } from "./resource-preview-context.js";
import type { ResourcePreviewContext } from "./resource-preview-context.js";

const renderControlTree = (
  root: NonNullable<ResourcePreviewData["ribbonBml"]>["tree"]
): string => {
  if (!root) return "";
  const rows: string[] = [];
  const stack = [{ control: root, level: 0 }];
  while (stack.length) {
    const item = stack.pop();
    if (!item) break;
    rows.push(`<tr><td class="peNumeric">${item.level}</td>` +
      `<td>${escapeHtml(item.control.reference === undefined ? item.control.kind :
        `${item.control.kind} @${item.control.reference}`)}</td>` +
      `<td class="peNumeric">${item.control.commandId ?? "–"}</td></tr>`);
    for (let index = item.control.children.length - 1; index >= 0; index -= 1) {
      const child = item.control.children[index];
      if (child) stack.push({ control: child, level: item.level + 1 });
    }
  }
  return `<h4>Control hierarchy</h4><div style="overflow-x:auto">` +
    `<table class="table peResourceNestedTable"><thead><tr><th>Level</th>` +
    `<th>Control</th><th>Command ID</th></tr></thead><tbody>` +
    rows.join("") + `</tbody></table></div>`;
};

const renderCommandResource = (
  resource: NonNullable<ResourcePreviewData["ribbonBml"]>["commands"][number]["resources"][number],
  context?: ResourcePreviewContext
): string => {
  if (resource.kind.toLowerCase().includes("image")) {
    const image = resolvedPreview(context, ["BITMAP", "PNG"], resource.resourceId)?.previewDataUrl;
    return image ? `<img class="peResourceImagePreview" src="${image}" alt="${escapeHtml(resource.kind)}" />` : "";
  }
  const text = resolvedPreview(context, ["STRING"], Math.floor(resource.resourceId / 16) + 1)?.stringTable
    ?.find(item => item.id === resource.resourceId)?.text;
  return text === undefined ? "" : escapeHtml(text);
};

export const renderRibbonBmlPreview = (
  ribbon: NonNullable<ResourcePreviewData["ribbonBml"]>, context?: ResourcePreviewContext
): string => {
  const rows = ribbon.commands.flatMap(command =>
    (command.resources.length ? command.resources : [null]).map(resource =>
      `<tr><td class="peNumeric">${command.id}</td>` +
      `<td>${resource ? escapeHtml(resource.kind) : "–"}</td>` +
      `<td class="peNumeric">${resource?.resourceId ?? "–"}</td>` +
      `<td class="peNumeric">${resource?.minimumDpi ?? "–"}</td>` +
      `<td>${resource ? renderCommandResource(resource, context) : ""}</td></tr>`));
  return `<p>Compiled Windows Ribbon: ${ribbon.commands.length} commands, ` +
    `${ribbon.strings.length} internal strings.</p>` +
    (ribbon.strings.length ? `<p class="smallNote">Internal strings: ` +
      escapeHtml(ribbon.strings.join(", ")) + `</p>` : "") +
    `<div style="overflow-x:auto"><table class="table peResourceNestedTable"><thead><tr>` +
    `<th>Command ID</th><th>Resource</th><th>Resource ID</th><th>Min DPI</th><th>Text / image</th>` +
    `</tr></thead><tbody>${rows.join("")}</tbody></table></div>` +
    renderControlTree(ribbon.tree);
};
