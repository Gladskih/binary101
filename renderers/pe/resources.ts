"use strict";

import { humanSize } from "../../binary-utils.js";
import { safe } from "../../html-utils.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import type { ResourceTree } from "../../analyzers/pe/resources-core.js";
import type { ResourceDetailGroup } from "../../analyzers/pe/resources-preview-types.js";
import { renderPreviewCell } from "./resource-preview-cell.js";

const formatLang = (lang: number | null | undefined): string => {
  if (lang == null) return "-";
  return "0x" + (Number(lang) >>> 0).toString(16).padStart(4, "0");
};

const formatCodePage = (codePage: number | null | undefined): string =>
  codePage ? String(codePage) : "-";

type PeWithResources = Pick<PeParseResult, "resources">;

export function renderResources(pe: PeParseResult | PeWithResources, out: string[]): void {
  const resources = (pe as PeWithResources).resources as
    | { top?: ResourceTree["top"]; detail?: ResourceDetailGroup[]; issues?: string[] }
    | null;
  if (!resources) return;
  const issues = (resources.issues || []).filter((issue): issue is string => Boolean(issue));

  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Resources</h4>`);
  out.push(
    `<div class="smallNote">Windows resources are organized as a three-level tree: ` +
      `type → name/ID → language. This view previews common standard resources ` +
      `such as icons, cursors, bitmaps, dialogs, menus, accelerators, message tables, ` +
      `version info, and heuristic payloads carried by RCDATA or custom types.</div>`
  );
  if (issues.length) {
    out.push(
      `<div class="smallNote" style="color:var(--warning-text,#b45309)">⚠ ${issues.map(safe).join(" · ")}</div>`
    );
  }

  if (resources.top?.length) {
    out.push(`<table class="table" style="margin-top:.5rem"><thead><tr><th>Type</th><th>Key kind</th><th>Leaf entries</th></tr></thead><tbody>`);
    for (const row of resources.top) {
      const typeName = safe(row.typeName || "(unknown)");
      const kind = row.kind === "name" ? "string name" : "numeric ID";
      out.push(`<tr><td>${typeName}</td><td>${kind}</td><td>${row.leafCount ?? 0}</td></tr>`);
    }
    out.push(`</tbody></table>`);
  }

  if (resources.detail?.length) {
    for (const group of resources.detail) {
      const typeName = safe(group.typeName || "(unknown)");
      const entryCount = group.entries?.length || 0;
      out.push(`<details style="margin-top:.75rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>${typeName}</b> — ${entryCount} entr${entryCount === 1 ? "y" : "ies"}</summary>`);
      if (entryCount) {
        out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>Name / ID</th><th>Lang</th><th>Size</th><th>CodePage</th><th>Preview</th></tr></thead><tbody>`);
        for (const entry of group.entries) {
          const displayName = entry.name ? safe(entry.name) : (entry.id != null ? `ID ${entry.id}` : "(unnamed)");
          for (const langEntry of entry.langs || []) {
            out.push(
              `<tr><td>${displayName}</td><td>${formatLang(langEntry.lang)}</td><td>${humanSize(
                langEntry.size || 0
              )}</td><td>${formatCodePage(langEntry.codePage)}</td><td>${renderPreviewCell(langEntry)}</td></tr>`
            );
          }
        }
        out.push(`</tbody></table>`);
      }
      out.push(`</details>`);
    }
  }

  out.push(`</section>`);
}
