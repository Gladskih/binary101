"use strict";

import type { ResourcePreviewData } from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtml } from "../../html-utils.js";

export const renderWevtTemplatePreview = (
  template: NonNullable<ResourcePreviewData["wevtTemplate"]>
): string =>
  `<p>Windows Event manifest v${escapeHtml(template.version)}; ` +
  `${template.providers.length} provider${template.providers.length === 1 ? "" : "s"}.</p>` +
  template.providers.map(provider =>
    `<h5>Provider <span class="mono">${escapeHtml(provider.guid)}</span></h5>` +
    (provider.messageId === null ? "" :
      `<p>Provider message ID: <span class="mono">${provider.messageId}</span></p>`) +
    `<p class="smallNote">Sections: ${escapeHtml(provider.elements.map(element =>
      element.kind || "unknown").join(", ") || "none")}</p>` +
    (provider.metadata.length ? `<table class="table peResourceNestedTable"><thead><tr>` +
      `<th>Kind</th><th>ID</th><th>Name</th><th>Message ID</th></tr></thead><tbody>` +
      provider.metadata.map(entry => `<tr><td>${escapeHtml(entry.kind)}</td>` +
        `<td class="mono">${escapeHtml(entry.id)}</td><td>${escapeHtml(entry.name ?? "–")}</td>` +
        `<td class="peNumeric">${entry.messageId ?? "–"}</td></tr>`).join("") +
      `</tbody></table>` : "") +
    `<div style="overflow-x:auto"><table class="table peResourceNestedTable"><thead><tr>` +
    `<th>Event ID</th><th>Version</th><th>Channel</th><th>Level</th><th>Opcode</th>` +
    `<th>Task</th><th>Keywords</th><th>Message ID</th><th>Template offset</th>` +
    `</tr></thead><tbody>` + provider.events.map(event =>
      `<tr><td class="peNumeric">${event.id}</td><td class="peNumeric">${event.version}</td>` +
      `<td class="peNumeric">${event.channel}</td><td class="peNumeric">${event.level}</td>` +
      `<td class="peNumeric">${event.opcode}</td><td class="peNumeric">${event.task}</td>` +
      `<td class="mono">${event.keywords}</td>` +
      `<td class="peNumeric" title="${escapeHtml(event.messageText ?? "")}">` +
      `${event.messageId ?? "–"}${event.messageText ?
        `<br><span dir="auto">${escapeHtml(event.messageText)}</span>` : ""}</td>` +
      `<td class="mono peNumeric">${event.templateOffset === null ? "–" :
        `0x${event.templateOffset.toString(16)}`}</td></tr>`).join("") +
    `</tbody></table></div>` +
    (provider.templates.length ? `<table class="table peResourceNestedTable"><thead><tr>` +
      `<th>Template GUID</th><th>Offset</th><th>Fields</th></tr></thead><tbody>` +
      provider.templates.map(template =>
        `<tr><td class="mono">${escapeHtml(template.guid)}</td>` +
        `<td class="mono peNumeric">0x${template.offset.toString(16)}</td>` +
        `<td>${escapeHtml(template.fields.map(field =>
          `${field.name ?? "(unnamed)"} (inType ${field.inputType}, ` +
          `outType ${field.outputType}, count ${field.count}, length ${field.length})`).join(", "))}` +
        `</td></tr>`).join("") + `</tbody></table>` : "")
  ).join("");
