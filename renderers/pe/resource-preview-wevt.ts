"use strict";

import type {
  ResourcePreviewData, ResourceWevtProvider, ResourceWevtTemplate
} from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtml } from "../../html-utils.js";
import { renderXmlPreview } from "./resource-preview-xml.js";

const renderTemplateReference = (
  offset: number | null, templates: Map<number, ResourceWevtTemplate>
): string => {
  if (offset === null) return "–";
  const template = templates.get(offset);
  return `0x${offset.toString(16)}` + (template
    ? `<br><span class="mono">${escapeHtml(template.guid)}</span>` +
      (template.xmlTree ? `<br>XML: &lt;${escapeHtml(template.xmlTree.name)}&gt;` : "") +
      (template.fields.length ? `<br>Fields: ${escapeHtml(template.fields.map(field =>
        field.name ?? "(unnamed)").join(", "))}` : "")
    : "");
};

const renderTemplates = (templates: ResourceWevtTemplate[]): string =>
  templates.length ? `<table class="table peResourceNestedTable"><thead><tr>` +
    `<th>Template GUID</th><th>Offset</th><th>Fields</th><th>Event XML</th>` +
    `</tr></thead><tbody>` + templates.map(template =>
      `<tr><td class="mono">${escapeHtml(template.guid)}</td>` +
      `<td class="mono peNumeric">0x${template.offset.toString(16)}</td>` +
      `<td>${escapeHtml(template.fields.map(field =>
        `${field.name ?? "(unnamed)"} (inType ${field.inputType}, ` +
        `outType ${field.outputType}, count ${field.count}, length ${field.length})`).join(", "))}` +
      `</td><td>${renderXmlPreview(undefined, template.xmlTree)}</td></tr>`).join("") +
    `</tbody></table>` : "";

const renderProvider = (provider: ResourceWevtProvider): string => {
  const templates = new Map(provider.templates.map(template => [template.offset, template]));
  return (
    `<h5>Provider <span class="mono">${escapeHtml(provider.guid)}</span></h5>` +
    (provider.messageId === null ? "" :
      `<p>Provider message ID: <span class="mono">${provider.messageId}</span>` +
      `${provider.messageText ? ` <span dir="auto">${escapeHtml(provider.messageText)}</span>` : ""}</p>`) +
    `<p class="smallNote">Sections: ${escapeHtml(provider.elements.map(element =>
      element.kind || "unknown").join(", ") || "none")}</p>` +
    (provider.metadata.length ? `<table class="table peResourceNestedTable"><thead><tr>` +
      `<th>Kind</th><th>ID</th><th>Name</th><th>Message ID</th></tr></thead><tbody>` +
      provider.metadata.map(entry => `<tr><td>${escapeHtml(entry.kind)}</td>` +
        `<td class="mono">${escapeHtml(entry.id)}</td><td>${escapeHtml(entry.name ?? "–")}</td>` +
        `<td class="peNumeric"${entry.messageText ?
          ` title="${escapeHtml(entry.messageText)}"` : ""}>` +
        `${entry.messageId ?? "–"}${entry.messageText ?
          `<br><span dir="auto">${escapeHtml(entry.messageText)}</span>` : ""}</td></tr>`).join("") +
      `</tbody></table>` : "") +
    (provider.maps?.length ? `<table class="table peResourceNestedTable"><thead><tr>` +
      `<th>Map</th><th>Name</th><th>Value</th><th>Message ID</th></tr></thead><tbody>` +
      provider.maps.flatMap(map => (map.entries.length ? map.entries : [null]).map(entry =>
        `<tr><td>${escapeHtml(map.kind)}</td><td>${escapeHtml(map.name ?? "–")}</td>` +
        `<td class="peNumeric">${entry?.value ?? "–"}</td>` +
        `<td class="peNumeric">${entry?.messageId ?? "–"}${entry?.messageText ?
          `<br><span dir="auto">${escapeHtml(entry.messageText)}</span>` : ""}</td></tr>`)).join("") +
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
      `<td class="mono peNumeric">${renderTemplateReference(event.templateOffset, templates)}` +
      `</td></tr>`).join("") +
    `</tbody></table></div>` +
    renderTemplates(provider.templates)
  );
};

export const renderWevtTemplatePreview = (
  template: NonNullable<ResourcePreviewData["wevtTemplate"]>
): string =>
  `<p>Windows Event manifest v${escapeHtml(template.version)}; ` +
  `${template.providers.length} provider${template.providers.length === 1 ? "" : "s"}.</p>` +
  template.providers.map(renderProvider).join("");
