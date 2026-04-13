"use strict";

import { humanSize } from "../../binary-utils.js";
import type { PeResources } from "../../analyzers/pe/resources/index.js";
import { safe } from "../../html-utils.js";
import { renderPeDiagnostics } from "./diagnostics.js";
import { renderPreviewCell } from "./resource-preview-cell.js";
import { formatWindowsLanguageName } from "./windows-language-names.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

const formatLang = (lang: number | null | undefined): string => {
  return formatWindowsLanguageName(lang);
};

const formatCodePage = (codePage: number | null | undefined): string =>
  codePage ? String(codePage) : "-";

const formatDirectoryVersion = (majorVersion: number, minorVersion: number): string =>
  majorVersion || minorVersion ? `${majorVersion}.${minorVersion}` : "-";

const formatDirectoryTimestamp = (timeDateStamp: number): string =>
  timeDateStamp ? `0x${timeDateStamp.toString(16).padStart(8, "0")}` : "-";

const formatResourcePathNode = (node: { id: number | null; name: string | null }): string =>
  node.name != null ? safe(node.name) : node.id != null ? `ID ${node.id}` : "(unnamed)";

export function renderResources(resources: PeResources, out: string[]): void {
  const issues = (resources.issues || []).filter((issue): issue is string => Boolean(issue));
  const extraPaths = (resources.paths || []).filter(path => path.nodes.length !== 3);
  const topRows = resources.top || [];
  out.push(
    renderPeSectionStart(
      "Resources",
      `${topRows.length} kind${topRows.length === 1 ? "" : "s"}`
    )
  );
  out.push(
    `<div class="smallNote">Windows resources usually follow a three-level tree: ` +
      `type → name/ID → language. Canonical .rsrc layout is directory entries → ` +
      `directory strings → data entries. This view previews common standard ` +
      `resources such as icons, cursors, bitmaps, dialogs, menus, accelerators, ` +
      `message tables, version info, and heuristic payloads carried by RCDATA or ` +
      `custom types.</div>`
  );
  if (issues.length) {
    out.push(renderPeDiagnostics("Resource warnings", issues));
  }
  if (topRows.length) {
    if (topRows.length > 12) {
      out.push(
        `<details style="margin-top:.75rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>Top-level resource kinds</b> - ${topRows.length} type bucket${topRows.length === 1 ? "" : "s"}</summary>`
      );
    }
    out.push(
      `<table class="table" style="margin-top:.5rem"><thead><tr><th>Type</th><th>Key kind</th><th>Leaf entries</th></tr></thead><tbody>`
    );
    for (const row of topRows) {
      const typeName = safe(row.typeName || "(unknown)");
      const kind = row.kind === "name" ? "string name" : "numeric ID";
      out.push(`<tr><td>${typeName}</td><td>${kind}</td><td>${row.leafCount ?? 0}</td></tr>`);
    }
    out.push(`</tbody></table>`);
    if (topRows.length > 12) {
      out.push(`</details>`);
    }
  }
  if (resources.directories?.length) {
    out.push(
      `<details style="margin-top:.75rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>IMAGE_RESOURCE_DIRECTORY</b> - ${resources.directories.length} table${resources.directories.length === 1 ? "" : "s"}</summary>`
    );
    out.push(
      `<table class="table" style="margin-top:.35rem"><thead><tr><th>Offset</th><th>Timestamp</th><th>Version</th><th>Named</th><th>ID</th></tr></thead><tbody>`
    );
    for (const directory of resources.directories) {
      out.push(
        `<tr><td class="mono">0x${directory.offset.toString(16)}</td><td class="mono">${formatDirectoryTimestamp(directory.timeDateStamp)}</td><td>${formatDirectoryVersion(directory.majorVersion, directory.minorVersion)}</td><td>${directory.namedEntries}</td><td>${directory.idEntries}</td></tr>`
      );
    }
    out.push(`</tbody></table></details>`);
  }
  if (resources.detail?.length) {
    for (const group of resources.detail) {
      const typeName = safe(group.typeName || "(unknown)");
      const entryCount = group.entries?.length || 0;
      out.push(
        `<details style="margin-top:.75rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>${typeName}</b> - ${entryCount} entr${entryCount === 1 ? "y" : "ies"}</summary>`
      );
      if (entryCount) {
        out.push(
          `<table class="table" style="margin-top:.35rem"><thead><tr><th>Name / ID</th><th>Lang</th><th>Size</th><th>CodePage</th><th>Preview</th></tr></thead><tbody>`
        );
        for (const entry of group.entries) {
          const displayName = entry.name
            ? safe(entry.name)
            : entry.id != null
              ? `ID ${entry.id}`
              : "(unnamed)";
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
  if (extraPaths.length) {
    out.push(
      `<details style="margin-top:.75rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>Additional resource paths</b> - ${extraPaths.length}</summary>`
    );
    out.push(
      `<table class="table" style="margin-top:.35rem"><thead><tr><th>Path</th><th>Size</th><th>CodePage</th><th>Data RVA</th></tr></thead><tbody>`
    );
    for (const path of extraPaths) {
      out.push(
        `<tr><td>${path.nodes.map(formatResourcePathNode).join(" / ")}</td><td>${humanSize(path.size)}</td><td>${formatCodePage(path.codePage)}</td><td class="mono">0x${path.dataRVA.toString(16)}</td></tr>`
      );
    }
    out.push(`</tbody></table></details>`);
  }
  out.push(renderPeSectionEnd());
}
