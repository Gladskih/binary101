"use strict";

import type {
  ResourceDialogControlPreview,
  ResourceDialogPreview
} from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtml, escapeHtmlText } from "../../html-utils.js";
import { formatControlStyle, formatDialogStyle, formatExtendedStyle } from "./dialog-style-values.js";
import type { ResourcePreviewContext } from "./resource-preview-context.js";
import { resolvedPreview } from "./resource-preview-context.js";
import { renderDialogControl } from "./resource-dialog-controls.js";
import { renderMenuResourceItems } from "./resource-menu.js";

const renderCreationData = (data: Uint8Array | undefined): string => data?.length
  ? `${data.length} bytes: ${Array.from(data.subarray(0, 32), byte =>
    byte.toString(16).padStart(2, "0")).join(" ")}${data.length > 32 ? " …" : ""}` : "-";

const renderDialogControls = (controls: ResourceDialogControlPreview[]): string => {
  const rows = controls.map((control, index) =>
    `<tr data-pe-dialog-property="${index}"><td>${escapeHtml(control.kind)}</td><td>${escapeHtml(control.title || "")}</td>` +
      `<td class="mono peNumeric">${control.id != null ? escapeHtml(control.id) : "-"}</td>` +
      `<td class="mono peNumeric">${control.x},${control.y} ` +
      `${control.width}x${control.height}</td>` +
      `<td class="mono peNumeric">${control.helpId ?? "-"}</td>` +
      `<td>${escapeHtml(formatControlStyle(control.style, control.kind))}</td>` +
      `<td>${escapeHtml(formatExtendedStyle(control.exStyle))}</td>` +
      `<td class="mono">${renderCreationData(control.creationData)}</td></tr>`
  ).join("");
  return `<div style="overflow-x:auto"><table class="table peResourceNestedTable peDialogControlsTable">` +
    `<thead><tr><th>Kind</th><th>Title</th><th>ID</th><th>Bounds (DLU)</th>` +
    `<th>Help ID</th><th>Style</th><th>Extended style</th><th>Creation data</th></tr></thead>` +
    `<tbody>${rows}</tbody></table></div>`;
};

const renderDialogFont = (dialog: ResourceDialogPreview): string => {
  if (!dialog.font) return "";
  const parts = [`${dialog.font.pointSize}pt ${dialog.font.typeface}`];
  if (dialog.font.weight != null) parts.push(`weight ${dialog.font.weight}`);
  if (dialog.font.italic) parts.push("italic");
  return `<div class="smallNote">Font: ${escapeHtml(parts.join(", "))}</div>`;
};

const renderDialogMetadata = (dialog: ResourceDialogPreview): string => {
  return [
    `<b>${escapeHtml(dialog.title || "(untitled dialog)")}</b>`,
    `${dialog.controls.length} controls`,
    dialog.templateKind === "extended" ? "DLGTEMPLATEEX" : "DLGTEMPLATE",
    dialog.menu ? `Menu: ${escapeHtml(dialog.menu)}` : "",
    dialog.className ? `Class: ${escapeHtml(dialog.className)}` : ""
  ].filter(Boolean).join(" - ");
};

const renderDialogMenu = (dialog: ResourceDialogPreview, context?: ResourcePreviewContext): string => {
  const menu = dialog.menu !== null ? resolvedPreview(context, ["MENU"], dialog.menu)?.menuPreview : null;
  return menu ? `<nav class="peDialog__menu">${menu.items.map(item =>
      `<details><summary>${escapeHtml(item.text ?? "")}</summary>` +
      renderMenuResourceItems(item.children) +
      `</details>`).join("")}</nav>` : "";
};

const dialogFontStyle = (dialog: ResourceDialogPreview): string =>
  `font-family:${escapeHtmlText(JSON.stringify(dialog.font?.typeface ?? "sans-serif"))};` +
  `font-size:${Math.max(1, dialog.font?.pointSize ?? 9)}pt;font-weight:${dialog.font?.weight ?? 400};font-style:${dialog.font?.italic ? "italic" : "normal"}`;

export const renderDialogPreview = (dialog: ResourceDialogPreview, context?: ResourcePreviewContext): string => {
  const meta = renderDialogMetadata(dialog);
  let tabOrder = 1;
  const direction = dialog.exStyle & 0x400000 ? "rtl" : "ltr";
  const controls = dialog.controls.map((control, index) => renderDialogControl(control, index, context,
    control.style & 0x10000 ? tabOrder++ : null, direction)).join("");
  return [
    `<div class="peDialog" data-pe-dialog data-pe-dialog-width="${Math.max(1, dialog.width)}" ` +
      `data-pe-dialog-height="${Math.max(1, dialog.height)}" style="${dialogFontStyle(dialog)}">`,
    `<div class="smallNote">${meta}</div>`,
    `<div class="smallNote">Style: ${escapeHtml(formatDialogStyle(dialog.style))}</div>`,
    `<div class="smallNote">Extended style: ${escapeHtml(formatExtendedStyle(dialog.exStyle))}</div>`,
    dialog.helpId != null ? `<div class="smallNote">Help ID: ${dialog.helpId}</div>` : "",
    renderDialogFont(dialog),
    `<p class="smallNote">Font metrics approximate Windows DLU in this browser. ` +
      `Application-defined drawing and runtime state are unavailable. ` +
      `DLGINIT ANSI text uses Windows-1252 when no code page is known.</p>`,
    `<div class="peDialog__tools"><label>Zoom <input type="range" min="25" max="200" ` +
      `value="100" data-pe-dialog-zoom aria-label="Dialog zoom" /></label>` +
      `<label><input type="checkbox" data-pe-dialog-tab-order /> Tab order</label>` +
      `<label><input type="checkbox" checked data-pe-dialog-hidden /> Show hidden controls</label></div>`,
    `<div class="peDialog__viewport"><div class="peDialog__window" style="background:var(--card);color:var(--text)">`,
    `<div class="peDialog__title">${escapeHtml(dialog.title || "(untitled dialog)")}</div>`,
    renderDialogMenu(dialog, context),
    `<div class="peDialog__client" data-pe-dialog-client dir="${direction}" ` +
      `style="width:calc(${Math.max(1, dialog.width)} * var(--pe-dlu-x));` +
      `height:calc(${Math.max(1, dialog.height)} * var(--pe-dlu-y));background:var(--bg)">${controls}</div>`,
    "</div></div>",
    renderDialogControls(dialog.controls),
    "</div>"
  ].join("");
};
