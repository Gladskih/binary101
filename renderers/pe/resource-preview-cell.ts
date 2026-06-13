"use strict";
import { escapeHtml } from "../../html-utils.js";
import type {
  ResourceAcceleratorEntryPreview,
  ResourceLangWithPreview,
  ResourceMenuItemPreview
} from "../../analyzers/pe/resources/preview/types.js";
import { renderDialogPreview } from "./resource-preview-dialog.js";
import { renderManifestPreview, renderManifestTree } from "./resource-preview-manifest.js";
import { renderMuiConfigPreview } from "./resource-preview-mui.js";
import { renderStructuredPreview, renderStructuredPreviewSummary } from "./resource-preview-structured.js";
import { renderVersionPreview } from "./resource-preview-version.js";

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
const findDetectedPreviewField = (langEntry: ResourceLangWithPreview): string | null =>
  langEntry.previewFields?.find(field => field.label === "Detected")?.value ?? null;

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
  if (langEntry.previewKind === "muiConfig" && langEntry.muiConfig) {
    return "MUI resource config";
  }
  const structuredSummary = renderStructuredPreviewSummary(langEntry);
  if (structuredSummary) return structuredSummary;
  if (langEntry.previewKind === "version") return "Version info";
  if (langEntry.previewKind === "text" && (langEntry.manifestInfo || langEntry.manifestTree)) {
    return "Manifest";
  }
  if (langEntry.previewKind === "text" || langEntry.previewKind === "html") {
    return findDetectedPreviewField(langEntry) || langEntry.previewKind;
  }
  if (langEntry.previewKind === "summary") {
    return findDetectedPreviewField(langEntry) || langEntry.previewKind;
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
  const structuredPreview = renderStructuredPreview(langEntry);
  if (structuredPreview) return structuredPreview + renderFields(langEntry) + renderIssues(langEntry);
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
  if (langEntry.previewKind === "version") {
    return [
      langEntry.versionInfo ? renderVersionPreview(langEntry.versionInfo) : "",
      renderFields(langEntry),
      renderIssues(langEntry)
    ].join("") || "-";
  }
  if (langEntry.previewKind === "stringTable" && Array.isArray(langEntry.stringTable)) {
    return renderStringTablePreview(langEntry);
  }
  if (langEntry.previewKind === "messageTable" && langEntry.messageTable?.messages) {
    return renderMessageTablePreview(langEntry);
  }
  if (langEntry.previewKind === "muiConfig" && langEntry.muiConfig) {
    return renderMuiConfigPreview(langEntry.muiConfig) + renderFields(langEntry) + renderIssues(langEntry);
  }
  const tailPreview = renderTailPreview(langEntry);
  if (tailPreview) return tailPreview;
  return renderIssues(langEntry) || renderManifestTree(langEntry.manifestInfo, langEntry.manifestTree) || renderFields(langEntry) || "-";
};
