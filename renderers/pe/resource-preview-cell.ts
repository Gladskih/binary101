"use strict";

import { safe } from "../../html-utils.js";
import type {
  ResourceAcceleratorEntryPreview,
  ResourceDialogControlPreview,
  ResourceDialogPreview,
  ResourceLangWithPreview,
  ResourceMenuItemPreview
} from "../../analyzers/pe/resources-preview-types.js";

const renderIssues = (langEntry: ResourceLangWithPreview): string => {
  const issues = (langEntry.previewIssues || []).filter((issue): issue is string => Boolean(issue));
  return issues.length
    ? `<div class="smallNote" style="color:var(--warning-text,#b45309)">⚠ ${issues.map(safe).join(" · ")}</div>`
    : "";
};

const renderFields = (langEntry: ResourceLangWithPreview): string => {
  const fields = langEntry.previewFields || [];
  if (!fields.length) return "";
  const rows = fields.map(field => `<li><span class="mono">${safe(field.label)}</span>: ${safe(field.value)}</li>`).join("");
  return `<ul class="smallNote" style="padding-left:1.1rem;margin:.25rem 0 0 0">${rows}</ul>`;
};

const renderDialogControls = (controls: ResourceDialogControlPreview[]): string => {
  const rows = controls.map(control =>
    `<tr><td>${safe(control.kind)}</td><td>${safe(control.title || "")}</td><td class="mono">${control.id != null ? safe(control.id) : "-"}</td><td class="mono">${control.x},${control.y} ${control.width}×${control.height}</td></tr>`
  ).join("");
  return `<table class="table" style="margin-top:.35rem"><thead><tr><th>Kind</th><th>Title</th><th>ID</th><th>Bounds</th></tr></thead><tbody>${rows}</tbody></table>`;
};

const renderDialogMockup = (dialog: ResourceDialogPreview): string => {
  const width = Math.max(1, dialog.width);
  const height = Math.max(1, dialog.height);
  const controls = dialog.controls.map(control => {
    const left = Math.max(0, Math.min(100, (control.x / width) * 100));
    const top = Math.max(0, Math.min(100, (control.y / height) * 100));
    const boxWidth = Math.max(8, Math.min(100 - left, (control.width / width) * 100));
    const boxHeight = Math.max(8, Math.min(100 - top, (control.height / height) * 100));
    const label = safe(control.title || control.kind);
    return `<div style="position:absolute;left:${left}%;top:${top}%;width:${boxWidth}%;height:${boxHeight}%;border:1px solid var(--border2);border-radius:4px;background:rgba(255,255,255,.55);padding:.1rem .2rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${label}</div>`;
  }).join("");
  return [
    '<div style="margin-top:.25rem">',
    `<div class="smallNote"><b>${safe(dialog.title || "(untitled dialog)")}</b> · ${dialog.controls.length} controls</div>`,
    `<div style="position:relative;margin-top:.25rem;width:220px;height:140px;border:1px solid var(--border2);border-radius:8px;background:linear-gradient(180deg,#f8fafc,#e5e7eb);overflow:hidden">`,
    `<div style="padding:.2rem .4rem;border-bottom:1px solid var(--border2);background:rgba(255,255,255,.65)">${safe(dialog.title || "(untitled dialog)")}</div>`,
    `<div style="position:absolute;left:0;right:0;top:1.75rem;bottom:0">${controls}</div>`,
    "</div>",
    renderDialogControls(dialog.controls),
    "</div>"
  ].join("");
};

const renderMenuItems = (items: ResourceMenuItemPreview[]): string => {
  if (!items.length) return "<div class=\"smallNote\">(empty menu)</div>";
  const rows = items.map(item => {
    const header = [
      item.text ? safe(item.text) : "<span class=\"smallNote\">(separator or unnamed)</span>",
      item.id != null ? `<span class="mono">#${safe(item.id)}</span>` : "",
      item.flags.length ? `<span class="smallNote">${safe(item.flags.join(", "))}</span>` : ""
    ].filter(Boolean).join(" ");
    const children = item.children.length ? renderMenuItems(item.children) : "";
    return `<li>${header}${children}</li>`;
  }).join("");
  return `<ul class="smallNote" style="padding-left:1.1rem;margin:.25rem 0 0 0">${rows}</ul>`;
};

const renderAcceleratorEntries = (entries: ResourceAcceleratorEntryPreview[]): string => {
  const rows = entries.map(entry => {
    const keyText = [...entry.modifiers, entry.key].join("+");
    return `<li><span class="mono">${safe(keyText)}</span> → <span class="mono">#${safe(entry.id)}</span></li>`;
  }).join("");
  return `<ul class="smallNote" style="padding-left:1.1rem;margin:0">${rows}</ul>`;
};

const renderVersionPreview = (langEntry: ResourceLangWithPreview): string => {
  const info = langEntry.versionInfo;
  if (!info) return "-";
  const parts: string[] = [];
  if (info.fileVersionString) parts.push(`File: ${safe(info.fileVersionString)}`);
  if (info.productVersionString) parts.push(`Product: ${safe(info.productVersionString)}`);
  const strings = (info.stringValues || [])
    .slice(0, 8)
    .map(entry => `<li><span class="mono">${safe(entry.key)}</span>: ${safe(entry.value)}</li>`)
    .join("");
  const translations = (info.translations || [])
    .map(entry => `0x${entry.languageId.toString(16).padStart(4, "0")}/CP${entry.codePage}`)
    .join(", ");
  return [
    parts.length ? `<div class="smallNote">${parts.join(" · ")}</div>` : "",
    translations ? `<div class="smallNote">Translations: ${safe(translations)}</div>` : "",
    strings ? `<ul class="smallNote" style="padding-left:1.1rem;margin:.25rem 0 0 0">${strings}</ul>` : "",
    renderFields(langEntry),
    renderIssues(langEntry)
  ].join("") || "-";
};

const renderFontPreview = (langEntry: ResourceLangWithPreview): string => {
  if (!langEntry.previewDataUrl) return renderFields(langEntry) + renderIssues(langEntry);
  const family = "peResourceFontPreview";
  return [
    "<style>",
    `@font-face{font-family:${family};src:url(${langEntry.previewDataUrl}) format('truetype');}`,
    "</style>",
    `<div style="font-family:${family},serif;font-size:1.05rem">Aa Bb Cc 123</div>`,
    renderFields(langEntry),
    renderIssues(langEntry)
  ].join("");
};

export const renderPreviewCell = (langEntry: ResourceLangWithPreview | null | undefined): string => {
  if (!langEntry) return "-";
  if (langEntry.previewKind === "image" && langEntry.previewDataUrl) {
    const mime = langEntry.previewMime || "image/png";
    return [
      `<img src="${langEntry.previewDataUrl}" alt="resource preview" title="${safe(mime)}" style="max-width:96px;max-height:72px;border-radius:4px;border:1px solid var(--border2)" />`,
      renderFields(langEntry),
      renderIssues(langEntry)
    ].join("");
  }
  if (langEntry.previewKind === "audio" && langEntry.previewDataUrl) {
    return [
      `<audio controls preload="metadata" src="${langEntry.previewDataUrl}"></audio>`,
      renderFields(langEntry),
      renderIssues(langEntry)
    ].join("");
  }
  if (langEntry.previewKind === "font") {
    return renderFontPreview(langEntry);
  }
  if (langEntry.previewKind === "text" && langEntry.textPreview) {
    return [
      `<div class="mono smallNote" style="white-space:pre-wrap;word-break:break-word">${safe(String(langEntry.textPreview))}</div>`,
      renderFields(langEntry),
      renderIssues(langEntry)
    ].join("");
  }
  if (langEntry.previewKind === "html" && langEntry.textPreview) {
    const encoding = langEntry.textEncoding ? `<div class="smallNote">Encoding: ${safe(langEntry.textEncoding)}</div>` : "";
    return [
      encoding,
      `<div class="mono smallNote" style="white-space:pre-wrap;word-break:break-word">${safe(String(langEntry.textPreview))}</div>`,
      renderFields(langEntry),
      renderIssues(langEntry)
    ].join("");
  }
  if (langEntry.previewKind === "version") return renderVersionPreview(langEntry);
  if (langEntry.previewKind === "stringTable" && Array.isArray(langEntry.stringTable)) {
    const list = langEntry.stringTable
      .map(entry => `<li><span class="mono">${entry.id != null ? `#${safe(entry.id)}` : "(index)"}</span> ${safe(entry.text || "")}</li>`)
      .join("");
    return `<ol class="smallNote" style="padding-left:1.25rem;margin:0">${list}</ol>${renderFields(langEntry)}${renderIssues(langEntry)}`;
  }
  if (langEntry.previewKind === "messageTable" && langEntry.messageTable?.messages) {
    const list = langEntry.messageTable.messages
      .map(message => {
        const text = Array.isArray(message.strings) ? message.strings.join(" | ") : "";
        return `<li><span class="mono">${message.id != null ? `#${safe(message.id)}` : "msg"}</span>: ${safe(text)}</li>`;
      })
      .join("");
    return `<ol class="smallNote" style="padding-left:1.25rem;margin:0">${list}</ol>${renderFields(langEntry)}${renderIssues(langEntry)}`;
  }
  if (langEntry.previewKind === "dialog" && langEntry.dialogPreview) {
    return renderDialogMockup(langEntry.dialogPreview) + renderFields(langEntry) + renderIssues(langEntry);
  }
  if (langEntry.previewKind === "menu" && langEntry.menuPreview) {
    return renderMenuItems(langEntry.menuPreview.items) + renderFields(langEntry) + renderIssues(langEntry);
  }
  if (langEntry.previewKind === "accelerator" && langEntry.acceleratorPreview) {
    return (
      renderAcceleratorEntries(langEntry.acceleratorPreview.entries) +
      renderFields(langEntry) +
      renderIssues(langEntry)
    );
  }
  if (langEntry.previewKind === "summary") {
    const rendered = renderFields(langEntry) + renderIssues(langEntry);
    return rendered || "-";
  }
  const issues = renderIssues(langEntry);
  const fields = renderFields(langEntry);
  return issues || fields || "-";
};
