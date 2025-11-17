"use strict";

import { humanSize } from "../../binary-utils.js";
import { safe } from "../../html-utils.js";

function formatLang(lang) {
  if (lang == null) return "-";
  const id = Number(lang) >>> 0;
  return "0x" + id.toString(16).padStart(4, "0");
}

function formatCodePage(codePage) {
  if (!codePage) return "-";
  return String(codePage);
}

function renderPreviewCell(langEntry) {
  if (!langEntry) return "-";
  const kind = langEntry.previewKind;
  if (kind === "image" && langEntry.previewDataUrl) {
    const mime = langEntry.previewMime || "image/png";
    return `<img src="${langEntry.previewDataUrl}" alt="icon" title="${safe(mime)}" style="max-width:64px;max-height:64px;border-radius:4px;border:1px solid var(--border2)" />`;
  }
  if (kind === "text" && langEntry.textPreview) {
    const text = String(langEntry.textPreview);
    const short = text.length > 280 ? `${text.slice(0, 277)}…` : text;
    return `<div class="mono smallNote" style="max-height:7.5rem;overflow:auto;white-space:pre-wrap;word-break:break-word">${safe(short)}</div>`;
  }
  if (kind === "version" && langEntry.versionInfo) {
    const info = langEntry.versionInfo;
    const parts = [];
    if (info.fileVersionString) parts.push(`File: ${safe(info.fileVersionString)}`);
    if (info.productVersionString) parts.push(`Product: ${safe(info.productVersionString)}`);
    return parts.length ? `<div class="smallNote">${parts.join(" · ")}</div>` : "-";
  }
  return "-";
}

export function renderResources(pe, out) {
  const resources = pe.resources;
  if (!resources) return;

  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Resources</h4>`);
  out.push(`<div class="smallNote">Windows resources are organized as a three-level tree: type → name/ID → language. Icons, version info, manifests and message tables live here.</div>`);

  if (resources.top?.length) {
    out.push(`<table class="table" style="margin-top:.5rem"><thead><tr><th>Type</th><th>Key kind</th><th>Leaf entries</th></tr></thead><tbody>`);
    for (const row of resources.top) {
      const typeName = safe(row.typeName || "(unknown)");
      const kind = row.kind === "name" ? "string name" : "numeric ID";
      const leafCount = row.leafCount ?? 0;
      out.push(`<tr><td>${typeName}</td><td>${kind}</td><td>${leafCount}</td></tr>`);
    }
    out.push(`</tbody></table>`);
  }

  if (resources.detail?.length) {
    for (const group of resources.detail) {
      const typeName = safe(group.typeName || "(unknown)");
      const entryCount = group.entries?.length || 0;
      out.push(`<details style="margin-top:.75rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>${typeName}</b> \u2014 ${entryCount} entr${entryCount === 1 ? "y" : "ies"}</summary>`);
      if (entryCount) {
        out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>Name / ID</th><th>Lang</th><th>Size</th><th>CodePage</th><th>Preview</th></tr></thead><tbody>`);
        for (const entry of group.entries) {
          const displayName = entry.name ? safe(entry.name) : (entry.id != null ? `ID ${entry.id}` : "(unnamed)");
          for (const langEntry of entry.langs || []) {
            const langText = formatLang(langEntry.lang);
            const sizeText = humanSize(langEntry.size || 0);
            const cpText = formatCodePage(langEntry.codePage);
            const preview = renderPreviewCell(langEntry);
            out.push(`<tr><td>${displayName}</td><td>${langText}</td><td>${sizeText}</td><td>${cpText}</td><td>${preview}</td></tr>`);
          }
        }
        out.push(`</tbody></table>`);
      }
      out.push(`</details>`);
    }
  }

  out.push(`</section>`);
}

