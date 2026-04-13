"use strict";

import { dd, safe } from "../../html-utils.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import {
  countFindings,
  countStandaloneFindings,
  countModulesWithFindingCodes,
  getModuleDisplayName,
  renderFindingSummary,
  summarizeLookupSources,
  summarizeRelations
} from "./import-linking-format.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

export function renderImportLinking(pe: PeWindowsParseResult, out: string[]): void {
  if (!pe.importLinking?.modules.length) return;
  const linkedModules = pe.importLinking.modules;
  const eagerImportCount = linkedModules.reduce((count, module) => count + module.imports.length, 0);
  const boundImportCount = linkedModules.reduce((count, module) => count + module.boundImports.length, 0);
  const delayImportCount = linkedModules.reduce((count, module) => count + module.delayImports.length, 0);
  const fallbackCount = pe.imports.entries.filter(entry => entry.lookupSource === "iat-fallback").length;
  const standaloneFindings = pe.importLinking.findings;
  const confirmedCount = countFindings(linkedModules, "confirmed") + countStandaloneFindings(standaloneFindings, "confirmed");
  const warningCount = countFindings(linkedModules, "warning") + countStandaloneFindings(standaloneFindings, "warning");
  const noteCount = countFindings(linkedModules, "info") + countStandaloneFindings(standaloneFindings, "info");
  out.push(
    renderPeSectionStart(
      "Import linkage",
      `${linkedModules.length} module${linkedModules.length === 1 ? "" : "s"}`
    )
  );
  out.push(`<div class="smallNote">This view cross-matches the normal import table, BOUND_IMPORT, DELAY_IMPORT, IMAGE_DIRECTORY_ENTRY_IAT, relevant section layout, and Load Config GuardFlags. It shows both documented relationships that were confirmed and non-canonical layouts that still decode cleanly.</div>`);
  out.push(`<dl>`);
  out.push(dd("Modules", String(linkedModules.length), "Unique module names after case-insensitive cross-matching."));
  out.push(dd("Eager imports", String(eagerImportCount), "Normal IMAGE_IMPORT_DESCRIPTOR entries."));
  out.push(dd("Bound imports", String(boundImportCount), "BOUND_IMPORT descriptors used for prebinding metadata."));
  out.push(dd("Delay-load imports", String(delayImportCount), "DELAY_IMPORT descriptors resolved on first use."));
  out.push(dd("IAT fallback descriptors", String(fallbackCount), "Import descriptors whose names came from FirstThunk because OriginalFirstThunk is 0."));
  out.push(dd("Validated checks", String(confirmedCount), "Cross-checks that matched the PE documentation or another Microsoft-documented layout."));
  out.push(dd("Warnings", String(warningCount), "Cross-checks that contradict documented or expected relationships."));
  out.push(dd("Notes", String(noteCount), "Cross-checks that are informative but not automatically invalid."));
  out.push(dd("Protected delay-load modules", String(countModulesWithFindingCodes(linkedModules, ["protected-delay-iat-own-section", "protected-delay-iat-separate-section"])), "Modules whose delay-load IAT layout was confirmed against Load Config GuardFlags and section placement."));
  out.push(`</dl>`);
  out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show linked modules (${linkedModules.length})</summary>`);
  out.push(`<div class="tableWrap"><table class="table" style="margin-top:.35rem"><thead><tr><th>Module</th><th>Eager</th><th>Bound</th><th>Delay</th><th>Eager lookup</th><th>Eager IAT</th><th>Delay IAT</th><th>Validated</th><th>Warnings / notes</th></tr></thead><tbody>`);
  linkedModules.forEach(linkedModule => {
    const eagerRelations = linkedModule.imports.map(linkedImport => linkedImport.iatDirectoryRelation);
    const delayRelations = linkedModule.delayImports.map(linkedImport => linkedImport.iatDirectoryRelation);
    const findings = linkedModule.findings ?? [];
    out.push(`<tr><td>${safe(getModuleDisplayName(pe, linkedModule))}</td><td>${linkedModule.imports.length || "-"}</td><td>${linkedModule.boundImports.length || "-"}</td><td>${linkedModule.delayImports.length || "-"}</td><td>${summarizeLookupSources(pe, linkedModule)}</td><td>${summarizeRelations(eagerRelations)}</td><td>${summarizeRelations(delayRelations)}</td><td>${renderFindingSummary(findings, "confirmed")}</td><td>${renderFindingSummary(findings, "warning")}${renderFindingSummary(findings, "info")}</td></tr>`);
  });
  out.push(`</tbody></table></div></details>`);
  out.push(renderPeSectionEnd());
}
