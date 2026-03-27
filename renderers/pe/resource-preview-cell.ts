"use strict";

import { safe } from "../../html-utils.js";
import type {
  ResourceAcceleratorEntryPreview,
  ResourceDialogControlPreview,
  ResourceDialogPreview,
  ResourceLangWithPreview,
  ResourceMenuItemPreview,
  ResourceVersionPreview
} from "../../analyzers/pe/resources/preview/types.js";
import { formatWindowsLanguageName } from "./windows-language-names.js";

const renderIssues = (langEntry: ResourceLangWithPreview): string => {
  const issues = (langEntry.previewIssues || []).filter((issue): issue is string => Boolean(issue));
  return issues.length
    ? `<div class="smallNote" style="color:var(--warning-text,#b45309)">WARNING: ${issues.map(safe).join(" · ")}</div>`
    : "";
};

const renderFields = (langEntry: ResourceLangWithPreview): string => {
  const fields = langEntry.previewFields || [];
  if (!fields.length) return "";
  const rows = fields
    .map(field => `<li><span class="mono">${safe(field.label)}</span>: ${safe(field.value)}</li>`)
    .join("");
  return `<ul class="smallNote" style="padding-left:1.1rem;margin:.25rem 0 0 0">${rows}</ul>`;
};

const renderDialogControls = (controls: ResourceDialogControlPreview[]): string => {
  const rows = controls.map(control =>
    `<tr><td>${safe(control.kind)}</td><td>${safe(control.title || "")}</td><td class="mono">${control.id != null ? safe(control.id) : "-"}</td><td class="mono">${control.x},${control.y} ${control.width}x${control.height}</td></tr>`
  ).join("");
  return `<table class="table" style="margin-top:.35rem"><thead><tr><th>Kind</th><th>Title</th><th>ID</th><th>Bounds</th></tr></thead><tbody>${rows}</tbody></table>`;
};

const renderDialogFont = (dialog: ResourceDialogPreview): string => {
  if (!dialog.font) return "";
  const parts = [`${dialog.font.pointSize}pt ${dialog.font.typeface}`];
  if (dialog.font.weight != null) parts.push(`weight ${dialog.font.weight}`);
  if (dialog.font.italic) parts.push("italic");
  return `<div class="smallNote">Font: ${safe(parts.join(", "))}</div>`;
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
    "color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap";
  const label = safe(control.title || control.kind);
  const kind = control.kind.toUpperCase();
  if (kind === "STATIC") {
    return `<div style="${shared};padding:.15rem .2rem;border:0;background:transparent">${label}</div>`;
  }
  if (kind === "EDIT" || kind === "LISTBOX" || kind === "COMBOBOX") {
    return `<div style="${shared};padding:.1rem .25rem;border:1px solid var(--border2);border-radius:4px;background:var(--bg)">${label}</div>`;
  }
  return `<div style="${shared};padding:.1rem .2rem;border:1px solid var(--border2);border-radius:4px;background:var(--card);display:flex;align-items:center;justify-content:center">${label}</div>`;
};

const renderDialogMockup = (dialog: ResourceDialogPreview): string => {
  const meta = [
    `<b>${safe(dialog.title || "(untitled dialog)")}</b>`,
    `${dialog.controls.length} controls`,
    dialog.templateKind === "extended" ? "DLGTEMPLATEEX" : "DLGTEMPLATE",
    dialog.menu ? `Menu: ${safe(dialog.menu)}` : "",
    dialog.className ? `Class: ${safe(dialog.className)}` : ""
  ].filter(Boolean).join(" · ");
  const topOffset = dialog.menu ? "3.1rem" : "1.75rem";
  const controls = dialog.controls.map(control => renderDialogControlBox(control, dialog)).join("");
  return [
    '<div style="margin-top:.25rem">',
    `<div class="smallNote">${meta}</div>`,
    renderDialogFont(dialog),
    `<div style="position:relative;margin-top:.25rem;width:${Math.max(220, Math.min(320, dialog.width * 2))}px;height:${Math.max(140, Math.min(240, dialog.height * 2))}px;border:1px solid var(--border2);border-radius:8px;background:var(--card);color:var(--text);overflow:hidden">`,
    `<div style="padding:.2rem .4rem;border-bottom:1px solid var(--border2);background:var(--bg);color:var(--text)">${safe(dialog.title || "(untitled dialog)")}</div>`,
    dialog.menu
      ? `<div style="padding:.15rem .4rem;border-bottom:1px solid var(--border2);background:var(--card)">${safe(dialog.menu)}</div>`
      : "",
    `<div style="position:absolute;left:0;right:0;top:${topOffset};bottom:0;background:var(--bg);font-size:${dialog.font?.pointSize ? Math.max(10, Math.min(16, dialog.font.pointSize + 1)) : 12}px">${controls}</div>`,
    "</div>",
    renderDialogControls(dialog.controls),
    "</div>"
  ].join("");
};

const renderMenuItems = (items: ResourceMenuItemPreview[]): string => {
  if (!items.length) return '<div class="smallNote">(empty menu)</div>';
  const rows = items.map(item => {
    const header = [
      item.text ? safe(item.text) : '<span class="smallNote">(separator or unnamed)</span>',
      item.id != null ? `<span class="mono">#${safe(item.id)}</span>` : "",
      item.flags.length ? `<span class="smallNote">${safe(item.flags.join(", "))}</span>` : ""
    ].filter(Boolean).join(" ");
    return `<li>${header}${item.children.length ? renderMenuItems(item.children) : ""}</li>`;
  }).join("");
  return `<ul class="smallNote" style="padding-left:1.1rem;margin:.25rem 0 0 0">${rows}</ul>`;
};

const renderAcceleratorEntries = (entries: ResourceAcceleratorEntryPreview[]): string => {
  const rows = entries.map(entry =>
    `<li><span class="mono">${safe([...entry.modifiers, entry.key].join("+"))}</span> -> <span class="mono">#${safe(entry.id)}</span></li>`
  ).join("");
  return `<ul class="smallNote" style="padding-left:1.1rem;margin:0">${rows}</ul>`;
};

const renderDefinitionRows = (rows: Array<{ label: string; value: string }>): string => {
  if (!rows.length) return "";
  const cells = rows
    .map(row =>
      `<div><span class="mono">${safe(row.label)}</span></div><div>${safe(row.value)}</div>`
    )
    .join("");
  return `<div class="smallNote" style="display:grid;grid-template-columns:max-content 1fr;gap:.15rem .55rem;margin-top:.2rem">${cells}</div>`;
};

const parseVersionTableTranslation = (
  table: string
): { languageId: number; codePage: number } | null => {
  // StringFileInfo table names encode LANGID and code page as 8 hex digits, e.g. 040904E4.
  // Source: https://learn.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource
  if (!/^[0-9a-fA-F]{8}$/.test(table)) return null;
  return {
    languageId: Number.parseInt(table.slice(0, 4), 16),
    codePage: Number.parseInt(table.slice(4), 16)
  };
};

const formatVersionTranslation = (languageId: number, codePage: number): string =>
  `${formatWindowsLanguageName(languageId)} / CP${codePage}`;

const formatVersionTableName = (table: string): string => {
  const translation = parseVersionTableTranslation(table);
  return translation
    ? formatVersionTranslation(translation.languageId, translation.codePage)
    : table;
};

const createTranslationKey = (languageId: number, codePage: number): string =>
  `${languageId}:${codePage}`;

const collectVersionTableTranslations = (info: ResourceVersionPreview): Set<string> => {
  const translations = new Set<string>();
  for (const entry of info.stringValues || []) {
    const translation = parseVersionTableTranslation(entry.table);
    if (!translation) continue;
    translations.add(createTranslationKey(translation.languageId, translation.codePage));
  }
  return translations;
};

const renderVersionTranslations = (
  info: ResourceVersionPreview,
  tableTranslations: Set<string>
): string => {
  const translations = (info.translations || []).filter(entry =>
    !tableTranslations.has(createTranslationKey(entry.languageId, entry.codePage))
  );
  if (!translations.length) return "";
  const rows = translations
    .map(entry => `<li>${safe(formatVersionTranslation(entry.languageId, entry.codePage))}</li>`)
    .join("");
  return `<div class="smallNote" style="margin-top:.35rem"><b>Declared translations</b><ul style="padding-left:1.1rem;margin:.2rem 0 0 0">${rows}</ul></div>`;
};

const renderVersionFixedInfo = (info: ResourceVersionPreview): string => {
  const rows = [
    info.fileVersionString
      ? { label: "FileVersion", value: info.fileVersionString }
      : null,
    info.productVersionString
      ? { label: "ProductVersion", value: info.productVersionString }
      : null
  ].filter((row): row is { label: string; value: string } => Boolean(row));
  return rows.length
    ? `<div class="smallNote"><b>Fixed version info</b>${renderDefinitionRows(rows)}</div>`
    : "";
};

const renderVersionStringTables = (info: ResourceVersionPreview): string => {
  if (!info.stringValues?.length) return "";
  const stringsByTable = new Map<string, Array<{ key: string; value: string }>>();
  for (const entry of info.stringValues) {
    if (entry.key === "FileVersion" && entry.value === info.fileVersionString) continue;
    if (entry.key === "ProductVersion" && entry.value === info.productVersionString) continue;
    const tableEntries = stringsByTable.get(entry.table) || [];
    tableEntries.push({ key: entry.key, value: entry.value });
    stringsByTable.set(entry.table, tableEntries);
  }
  return [...stringsByTable.entries()].map(([table, values]) =>
    values.length
      ? `<div class="smallNote" style="margin-top:.35rem"><b>${safe(formatVersionTableName(table))}</b>${renderDefinitionRows(values.map(value => ({ label: value.key, value: value.value })))}</div>`
      : ""
  ).join("");
};

const renderVersionPreview = (langEntry: ResourceLangWithPreview): string => {
  const info = langEntry.versionInfo;
  if (!info) return "-";
  const tableTranslations = collectVersionTableTranslations(info);
  return [
    renderVersionFixedInfo(info),
    renderVersionTranslations(info, tableTranslations),
    renderVersionStringTables(info),
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
    return [
      `<img src="${langEntry.previewDataUrl}" alt="resource preview" title="${safe(langEntry.previewMime || "image/png")}" style="max-width:96px;max-height:72px;border-radius:4px;border:1px solid var(--border2)" />`,
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
  if (langEntry.previewKind === "font") return renderFontPreview(langEntry);
  if (langEntry.previewKind === "text" && langEntry.textPreview) {
    return [
      `<div class="mono smallNote" style="white-space:pre-wrap;word-break:break-word">${safe(String(langEntry.textPreview))}</div>`,
      renderFields(langEntry),
      renderIssues(langEntry)
    ].join("");
  }
  if (langEntry.previewKind === "html" && langEntry.textPreview) {
    return [
      langEntry.textEncoding
        ? `<div class="smallNote">Encoding: ${safe(langEntry.textEncoding)}</div>`
        : "",
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
    return renderAcceleratorEntries(langEntry.acceleratorPreview.entries) +
      renderFields(langEntry) +
      renderIssues(langEntry);
  }
  if (langEntry.previewKind === "summary") {
    const rendered = renderFields(langEntry) + renderIssues(langEntry);
    return rendered || "-";
  }
  return renderIssues(langEntry) || renderFields(langEntry) || "-";
};
