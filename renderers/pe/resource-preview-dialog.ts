"use strict";

import type {
  ResourceDialogControlPreview,
  ResourceDialogPreview
} from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtml } from "../../html-utils.js";

const renderDialogControls = (controls: ResourceDialogControlPreview[]): string => {
  const rows = controls.map(control =>
    `<tr><td>${escapeHtml(control.kind)}</td><td>${escapeHtml(control.title || "")}</td>` +
      `<td class="mono peNumeric">${control.id != null ? escapeHtml(control.id) : "-"}</td>` +
      `<td class="mono peNumeric">${control.x},${control.y} ` +
      `${control.width}x${control.height}</td></tr>`
  ).join("");
  return `<table class="table peResourceNestedTable peDialogControlsTable">` +
    `<thead><tr><th>Kind</th><th>Title</th><th>ID</th><th>Bounds</th></tr></thead>` +
    `<tbody>${rows}</tbody></table>`;
};

const renderDialogFont = (dialog: ResourceDialogPreview): string => {
  if (!dialog.font) return "";
  const parts = [`${dialog.font.pointSize}pt ${dialog.font.typeface}`];
  if (dialog.font.weight != null) parts.push(`weight ${dialog.font.weight}`);
  if (dialog.font.italic) parts.push("italic");
  return `<div class="smallNote">Font: ${escapeHtml(parts.join(", "))}</div>`;
};

const renderDialogControlBox = (
  control: ResourceDialogControlPreview,
  dialog: ResourceDialogPreview
): string => {
  const left = Math.max(0, Math.min(100, (control.x / Math.max(1, dialog.width)) * 100));
  const top = Math.max(0, Math.min(100, (control.y / Math.max(1, dialog.height)) * 100));
  const width = Math.max(
    8,
    Math.min(100 - left, (control.width / Math.max(1, dialog.width)) * 100)
  );
  const height = Math.max(
    8,
    Math.min(100 - top, (control.height / Math.max(1, dialog.height)) * 100)
  );
  const shared =
    `position:absolute;left:${left}%;top:${top}%;width:${width}%;height:${height}%;` +
    "color:var(--text);line-height:1.15;overflow:hidden;text-overflow:ellipsis;white-space:nowrap";
  const label = escapeHtml(control.title || control.kind);
  const kind = control.kind.toUpperCase();
  if (kind === "STATIC") {
    return `<div style="${shared};z-index:1;padding:.15rem .2rem;border:0;background:transparent">${label}</div>`;
  }
  if (kind === "EDIT" || kind === "LISTBOX" || kind === "COMBOBOX") {
    return `<div style="${shared};z-index:2;padding:.1rem .25rem;border:1px solid var(--border2);border-radius:4px;background:var(--bg)">${label}</div>`;
  }
  return `<div style="${shared};z-index:2;padding:.1rem .2rem;border:1px solid var(--border2);border-radius:4px;background:var(--card);display:flex;align-items:center;justify-content:center">${label}</div>`;
};

export const renderDialogPreview = (dialog: ResourceDialogPreview): string => {
  const meta = [
    `<b>${escapeHtml(dialog.title || "(untitled dialog)")}</b>`,
    `${dialog.controls.length} controls`,
    dialog.templateKind === "extended" ? "DLGTEMPLATEEX" : "DLGTEMPLATE",
    dialog.menu ? `Menu: ${escapeHtml(dialog.menu)}` : "",
    dialog.className ? `Class: ${escapeHtml(dialog.className)}` : ""
  ].filter(Boolean).join(" - ");
  const topOffset = dialog.menu ? "3.1rem" : "1.75rem";
  const controls = dialog.controls.map(control => renderDialogControlBox(control, dialog)).join("");
  return [
    '<div style="margin-top:.25rem">',
    `<div class="smallNote">${meta}</div>`,
    renderDialogFont(dialog),
    `<div style="position:relative;margin-top:.25rem;width:${Math.max(220, Math.min(320, dialog.width * 2))}px;height:${Math.max(140, Math.min(240, dialog.height * 2))}px;border:1px solid var(--border2);border-radius:8px;background:var(--card);color:var(--text);overflow:hidden">`,
    `<div style="padding:.2rem .4rem;border-bottom:1px solid var(--border2);background:var(--bg);color:var(--text)">${escapeHtml(dialog.title || "(untitled dialog)")}</div>`,
    dialog.menu
      ? `<div style="padding:.15rem .4rem;border-bottom:1px solid var(--border2);background:var(--card)">${escapeHtml(dialog.menu)}</div>`
      : "",
    `<div style="position:absolute;left:0;right:0;top:${topOffset};bottom:0;background:var(--bg);font-size:${dialog.font?.pointSize ? Math.max(10, Math.min(16, dialog.font.pointSize + 1)) : 12}px">${controls}</div>`,
    "</div>",
    renderDialogControls(dialog.controls),
    "</div>"
  ].join("");
};
