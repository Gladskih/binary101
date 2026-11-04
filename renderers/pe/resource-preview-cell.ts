"use strict";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { escapeHtml } from "../../html-utils.js";
import type {
  ResourceAcceleratorEntryPreview,
  ResourcePreviewWithIssues
} from "../../analyzers/pe/resources/preview/types.js";
import { renderMenuResourceItems } from "./resource-menu.js";
import { renderDialogPreview } from "./resource-preview-dialog.js";
import { renderManifestPreview, renderManifestTree } from "./resource-preview-manifest.js";
import { renderMuiConfigPreview } from "./resource-preview-mui.js";
import { renderStructuredPreview, renderStructuredPreviewSummary } from "./resource-preview-structured.js";
import { renderVersionPreview } from "./resource-preview-version.js";
import type { ResourcePreviewContext } from "./resource-preview-context.js";
import { renderImageGroupPreview } from "./resource-preview-image-group.js";
import { renderResourceDocumentTemplates } from "./resource-document-templates.js";

const renderIssues = (langEntry: ResourcePreviewWithIssues): string => {
  const issues = (langEntry.previewIssues || []).filter((issue): issue is string => Boolean(issue));
  return issues.length
    ? `<div class="smallNote" style="color:var(--warning-text,#b45309)">WARNING: ${issues.map(escapeHtml).join(" - ")}</div>`
    : "";
};
const renderFields = (langEntry: ResourcePreviewWithIssues): string => {
  const fields = langEntry.previewFields || [];
  if (!fields.length) return "";
  const rows = fields
    .map(field => `<tr><th scope="row">${escapeHtml(field.label)}</th><td>${escapeHtml(field.value)}</td></tr>`)
    .join("");
  return `<table class="table peResourceFieldTable"><tbody>${rows}</tbody></table>`;
};
const renderAcceleratorEntries = (entries: ResourceAcceleratorEntryPreview[]): string => {
  const rows = entries.map(entry =>
    `<tr><td class="mono">${escapeHtml([...entry.modifiers, entry.key].join("+"))}</td>` +
      `<td class="mono peNumeric">#${escapeHtml(entry.id)}</td></tr>`
  ).join("");
  return `<table class="table peResourceNestedTable"><thead><tr><th>Shortcut</th>` +
    `<th>Command ID</th></tr></thead><tbody>${rows}</tbody></table>`;
};
const findDetectedPreviewField = (langEntry: ResourcePreviewWithIssues): string | null =>
  langEntry.previewFields?.find(field => field.label === "Detected")?.value ?? null;

const renderFontPreview = (langEntry: ResourcePreviewWithIssues): string => {
  if (!langEntry.previewDataUrl) return renderFields(langEntry) + renderIssues(langEntry);
  const family = `peResourceFont${bytesToHex(sha256(new TextEncoder().encode(langEntry.previewDataUrl)))}`;
  const format = new Map([["font/otf", "opentype"], ["font/woff", "woff"],
    ["font/woff2", "woff2"]]).get(langEntry.previewMime ?? "") ?? "truetype";
  return [
    "<style>",
    `@font-face{font-family:${family};src:url(${langEntry.previewDataUrl}) format('${format}');}`,
    "</style>",
    `<div class="peResourceFontSample" style="font-family:${family},serif">Aa Bb Cc 123</div>`,
    renderFields(langEntry),
    renderIssues(langEntry)
  ].join("");
};
const renderStringTablePreview = (langEntry: ResourcePreviewWithIssues): string => {
  const rows = (langEntry.stringTable || [])
    .map(entry =>
      `<tr><td class="mono peNumeric">` +
      `${entry.id != null ? `#${escapeHtml(entry.id)}` : "(index)"}</td>` +
      `<td dir="auto">${escapeHtml(entry.text || "")}</td></tr>`
    )
    .join("");
  return `<table class="table peResourceNestedTable peResourceTextTable">` +
    `<thead><tr><th>ID</th><th>String</th></tr></thead><tbody>${rows}</tbody></table>` +
    `${renderResourceDocumentTemplates(langEntry)}${renderFields(langEntry)}${renderIssues(langEntry)}`;
};
const renderMessageTablePreview = (langEntry: ResourcePreviewWithIssues): string => {
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
const countSummary = (entry: ResourcePreviewWithIssues): string | null => {
  if (entry.previewKind === "dialog" && entry.dialogPreview) return `${entry.dialogPreview.controls.length} controls`;
  if (entry.previewKind === "stringTable" && entry.stringTable) return `${entry.stringTable.length} strings`;
  if (entry.previewKind === "messageTable" && entry.messageTable) return `${entry.messageTable.messages.length} messages`;
  return null;
};
export const renderPreviewSummary = (entry: ResourcePreviewWithIssues | null | undefined): string => {
  if (!entry?.previewKind) return "-";
  const count = countSummary(entry);
  if (count) return count;
  if (entry.previewKind === "text" && (entry.manifestInfo || entry.manifestTree)) return "Manifest";
  return renderStructuredPreviewSummary(entry) ?? summaryLabel(entry);
};
const summaryLabel = (entry: ResourcePreviewWithIssues): string => new Map([
    ["version", "Version info"], ["muiConfig", "MUI resource config"]
  ]).get(entry.previewKind ?? "") ?? findDetectedPreviewField(entry) ?? entry.previewKind ?? "-";

const renderText = (entry: ResourcePreviewWithIssues): string => {
  if (!entry.textPreview) return "";
  if (entry.manifestInfo || entry.manifestTree) return renderManifestPreview(String(entry.textPreview),
    entry.manifestInfo, entry.manifestTree, entry.manifestValidation);
  const encoding = entry.previewKind === "html" && entry.textEncoding ?
    `<div class="smallNote">Encoding: ${escapeHtml(entry.textEncoding)}</div>` : "";
  return encoding + `<div class="mono smallNote" style="white-space:pre-wrap;word-break:break-word">${escapeHtml(String(entry.textPreview))}</div>`;
};
const renderImage = (entry: ResourcePreviewWithIssues): string => entry.previewDataUrl
  ? `<img class="peResourceImagePreview" src="${entry.previewDataUrl}" alt="resource preview" title="${escapeHtml(entry.previewMime || "image/png")}" />` : "";
const renderAudio = (entry: ResourcePreviewWithIssues): string => entry.previewDataUrl
  ? `<audio controls preload="metadata" src="${entry.previewDataUrl}"></audio>` : "";

const bodyRenderers = new Map<string, (entry: ResourcePreviewWithIssues) => string>([
  ["text", renderText], ["html", renderText], ["image", renderImage], ["audio", renderAudio],
  ["version", entry => entry.versionInfo ? renderVersionPreview(entry.versionInfo) : ""],
  ["muiConfig", entry => entry.muiConfig ? renderMuiConfigPreview(entry.muiConfig) : ""],
  ["menu", entry => entry.menuPreview ? renderMenuResourceItems(entry.menuPreview.items) : ""],
  ["accelerator", entry => entry.acceleratorPreview ? renderAcceleratorEntries(entry.acceleratorPreview.entries) : ""]
]);

const contextualPreview = (entry: ResourcePreviewWithIssues,
  context: ResourcePreviewContext | undefined): string | null => {
  if (entry.previewKind === "dialog" && entry.dialogPreview) return renderDialogPreview(entry.dialogPreview, context);
  if (!context) return null;
  if (entry.imageGroup) return renderImageGroupPreview(entry.imageGroup, context);
  if (entry.previewKind !== "deferred") return null;
  const source = context.source;
  return `<button type="button" data-pe-resource-preview="${source.group}-${source.entry}-${source.language}">` +
    "Preview complete resource</button><p class=\"smallNote\">Large media preview is loaded on request.</p>";
};

const completeRenderers = new Map<string, (entry: ResourcePreviewWithIssues) => string>([
  ["font", renderFontPreview], ["stringTable", renderStringTablePreview], ["messageTable", renderMessageTablePreview]
]);

const renderPreviewBody = (entry: ResourcePreviewWithIssues,
  registryTableId?: string, context?: ResourcePreviewContext): string => {
  const body = contextualPreview(entry, context) ?? bodyRenderers.get(entry.previewKind ?? "")?.(entry) ??
    renderStructuredPreview(entry, registryTableId, context) ??
    renderManifestTree(entry.manifestInfo, entry.manifestTree);
  return (body ?? "") + renderFields(entry) + renderIssues(entry) || "-";
};

export const renderPreviewCell = (
  entry: ResourcePreviewWithIssues | null | undefined, registryTableId?: string,
  context?: ResourcePreviewContext
): string => {
  if (!entry) return "-";
  const complete = completeRenderers.get(entry.previewKind ?? "");
  if (complete) return complete(entry);
  return renderPreviewBody(entry, registryTableId, context);
};
