"use strict";
import { escapeHtml } from "../../html-utils.js";
import type {
  ResourceAcceleratorEntryPreview,
  ResourceLangWithPreview,
  ResourceMenuItemPreview,
  ResourceVersionPreview
} from "../../analyzers/pe/resources/preview/types.js";
import { formatWindowsLanguageName } from "./windows-language-names.js";
import { renderDialogPreview } from "./resource-preview-dialog.js";
import { renderManifestPreview, renderManifestTree } from "./resource-preview-manifest.js";
const renderIssues = (langEntry: ResourceLangWithPreview): string => {
  const issues = (langEntry.previewIssues || []).filter((issue): issue is string => Boolean(issue));
  return issues.length
    ? `<div class="smallNote" style="color:var(--warning-text,#b45309)">WARNING: ${issues.map(escapeHtml).join(" - ")}</div>`
    : "";
};
const renderFields = (langEntry: ResourceLangWithPreview): string => {
  const fields = langEntry.previewFields || [];
  if (!fields.length) return "";
  const rows = fields
    .map(field => `<tr><th scope="row">${escapeHtml(field.label)}</th><td>${escapeHtml(field.value)}</td></tr>`)
    .join("");
  return `<table class="table peResourceFieldTable"><tbody>${rows}</tbody></table>`;
};
const renderMenuItems = (items: ResourceMenuItemPreview[]): string => {
  if (!items.length) return '<div class="smallNote">(empty menu)</div>';
  const rows = items.map(item => {
    const header = [
      item.text ? escapeHtml(item.text) : '<span class="smallNote">(separator or unnamed)</span>',
      item.id != null ? `<span class="mono">#${escapeHtml(item.id)}</span>` : "",
      item.flags.length ? `<span class="smallNote">${escapeHtml(item.flags.join(", "))}</span>` : ""
    ].filter(Boolean).join(" ");
    return `<li>${header}${item.children.length ? renderMenuItems(item.children) : ""}</li>`;
  }).join("");
  return `<ul class="smallNote" style="padding-left:1.1rem;margin:.25rem 0 0 0">${rows}</ul>`;
};
const renderAcceleratorEntries = (entries: ResourceAcceleratorEntryPreview[]): string => {
  const rows = entries.map(entry =>
    `<tr><td class="mono">${escapeHtml([...entry.modifiers, entry.key].join("+"))}</td>` +
      `<td class="mono peNumeric">#${escapeHtml(entry.id)}</td></tr>`
  ).join("");
  return `<table class="table peResourceNestedTable"><thead><tr><th>Shortcut</th>` +
    `<th>Command ID</th></tr></thead><tbody>${rows}</tbody></table>`;
};
const renderDefinitionRows = (rows: Array<{ label: string; value: string }>): string => {
  if (!rows.length) return "";
  const cells = rows
    .map(row =>
      `<div><span class="mono">${escapeHtml(row.label)}</span></div>` +
      `<div style="min-width:0;overflow-wrap:anywhere">${escapeHtml(row.value)}</div>`
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
    .map(entry => `<li>${escapeHtml(formatVersionTranslation(entry.languageId, entry.codePage))}</li>`)
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
      ? `<div class="smallNote" style="margin-top:.35rem"><b>${escapeHtml(formatVersionTableName(table))}</b>${renderDefinitionRows(values.map(value => ({ label: value.key, value: value.value })))}</div>`
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
    `<div class="peResourceFontSample" style="font-family:${family},serif">Aa Bb Cc 123</div>`,
    renderFields(langEntry),
    renderIssues(langEntry)
  ].join("");
};
const renderStringTablePreview = (langEntry: ResourceLangWithPreview): string => {
  const rows = (langEntry.stringTable || [])
    .map(entry =>
      `<tr><td class="mono peNumeric">` +
      `${entry.id != null ? `#${escapeHtml(entry.id)}` : "(index)"}</td>` +
      `<td dir="auto">${escapeHtml(entry.text || "")}</td></tr>`
    )
    .join("");
  return `<table class="table peResourceNestedTable peResourceTextTable">` +
    `<thead><tr><th>ID</th><th>String</th></tr></thead><tbody>${rows}</tbody></table>` +
    `${renderFields(langEntry)}${renderIssues(langEntry)}`;
};
const renderMessageTablePreview = (langEntry: ResourceLangWithPreview): string => {
  const rows = (langEntry.messageTable?.messages || [])
    .map(message => {
      const text = Array.isArray(message.strings) ? message.strings.join(" | ") : "";
      return `<tr><td class="mono peNumeric">#${escapeHtml(message.id)}</td>` +
        `<td dir="auto">${escapeHtml(text)}</td></tr>`;
    })
    .join("");
  const truncated = langEntry.messageTable?.truncated
    ? `<div class="smallNote">Preview stopped before the full message table.</div>`
    : "";
  return `<table class="table peResourceNestedTable peResourceTextTable">` +
    `<thead><tr><th>Message ID</th><th>Text</th></tr></thead><tbody>${rows}</tbody></table>` +
    `${truncated}${renderFields(langEntry)}${renderIssues(langEntry)}`;
};
export const renderPreviewSummary = (
  langEntry: ResourceLangWithPreview | null | undefined
): string => {
  if (!langEntry?.previewKind) return "-";
  if (langEntry.previewKind === "dialog" && langEntry.dialogPreview) {
    return `${langEntry.dialogPreview.controls.length} controls`;
  }
  if (langEntry.previewKind === "stringTable" && Array.isArray(langEntry.stringTable)) {
    return `${langEntry.stringTable.length} strings`;
  }
  if (langEntry.previewKind === "messageTable" && langEntry.messageTable?.messages) {
    return `${langEntry.messageTable.messages.length} messages`;
  }
  if (langEntry.previewKind === "version") return "Version info";
  if (langEntry.previewKind === "text" && (langEntry.manifestInfo || langEntry.manifestTree)) {
    return "Manifest";
  }
  return langEntry.previewKind;
};
const renderTailPreview = (langEntry: ResourceLangWithPreview): string | null => {
  if (langEntry.previewKind === "dialog" && langEntry.dialogPreview) {
    return renderDialogPreview(langEntry.dialogPreview) + renderFields(langEntry) + renderIssues(langEntry);
  }
  if (langEntry.previewKind === "menu" && langEntry.menuPreview) {
    return renderMenuItems(langEntry.menuPreview.items) + renderFields(langEntry) + renderIssues(langEntry);
  }
  if (langEntry.previewKind === "accelerator" && langEntry.acceleratorPreview) {
    return renderAcceleratorEntries(langEntry.acceleratorPreview.entries) +
      renderFields(langEntry) +
      renderIssues(langEntry);
  }
  if (langEntry.previewKind === "summary") return renderFields(langEntry) + renderIssues(langEntry) || "-";
  return null;
};

export const renderPreviewCell = (langEntry: ResourceLangWithPreview | null | undefined): string => {
  if (!langEntry) return "-";
  if (langEntry.previewKind === "image" && langEntry.previewDataUrl) {
    return [
      `<img class="peResourceImagePreview" src="${langEntry.previewDataUrl}" ` +
        `alt="resource preview" title="${escapeHtml(langEntry.previewMime || "image/png")}" />`,
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
    if (langEntry.manifestInfo || langEntry.manifestTree) {
      return renderManifestPreview(
        String(langEntry.textPreview),
        langEntry.manifestInfo,
        langEntry.manifestTree,
        langEntry.manifestValidation
      ) + renderFields(langEntry) + renderIssues(langEntry);
    }
    return [
      `<div class="mono smallNote" style="white-space:pre-wrap;word-break:break-word">${escapeHtml(String(langEntry.textPreview))}</div>`,
      renderFields(langEntry),
      renderIssues(langEntry)
    ].join("");
  }
  if (langEntry.previewKind === "html" && langEntry.textPreview) {
    return [
      langEntry.textEncoding
        ? `<div class="smallNote">Encoding: ${escapeHtml(langEntry.textEncoding)}</div>`
        : "",
      `<div class="mono smallNote" style="white-space:pre-wrap;word-break:break-word">${escapeHtml(String(langEntry.textPreview))}</div>`,
      renderFields(langEntry),
      renderIssues(langEntry)
    ].join("");
  }
  if (langEntry.previewKind === "version") return renderVersionPreview(langEntry);
  if (langEntry.previewKind === "stringTable" && Array.isArray(langEntry.stringTable)) {
    return renderStringTablePreview(langEntry);
  }
  if (langEntry.previewKind === "messageTable" && langEntry.messageTable?.messages) {
    return renderMessageTablePreview(langEntry);
  }
  const tailPreview = renderTailPreview(langEntry);
  if (tailPreview) return tailPreview;
  return renderIssues(langEntry) || renderManifestTree(langEntry.manifestInfo, langEntry.manifestTree) || renderFields(langEntry) || "-";
};
