"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import {
  countModulesWithFindingCodes,
  countRelation,
  describeSectionForRva,
  filterFindings,
  filterStandaloneFindings,
  findLinkedDelayImportDescriptor,
  findLinkedModuleForBoundImport,
  findLinkedModuleForDelayImport,
  findLinkedModuleForImport,
  findLinkedImportDescriptor,
  renderDeclaredIatRelation,
  renderBinding,
  renderDelayGuardContext,
  renderDelaySectionContext,
  renderFindingRows,
  renderFindingSummary,
  renderImportNamesForIndices,
  renderIatRelation,
  renderLookupSource
} from "./import-linking-format.js";
import {
  renderImportLibraryInfoNote,
  renderImportLibraryNameWithInfo
} from "./import-library-info.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import {
  directIatEntrySize,
  directIatReferenceCounts
} from "./direct-iat-references.js";
import { renderImportFunctionTable } from "./import-function-table.js";

export { renderImportLinking } from "./import-linking-section.js";

export const PE_IMPORTS_PANEL_ID = "peImportsPanel";
export const PE_DELAY_IMPORTS_PANEL_ID = "peDelayImportsPanel";

const renderImportsContent = (pe: PeWindowsParseResult, out: string[]): void => {
  if (!pe.imports.entries.length && !pe.imports.warning) return;
  const counts = directIatReferenceCounts(pe);
  const entrySize = directIatEntrySize(pe);
  out.push(
    renderPeSectionStart(
      "Import table",
      `${pe.imports.entries.length} module${pe.imports.entries.length === 1 ? "" : "s"}`,
      PE_IMPORTS_PANEL_ID
    )
  );
  out.push(`<div class="smallNote">Each IMAGE_IMPORT_DESCRIPTOR names one DLL and points to two tables: OriginalFirstThunk normally gives the lookup names, while FirstThunk gives the runtime IAT slots that the loader patches.</div>`);
  if (pe.imports.warning) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${escapeHtml(pe.imports.warning)}</div>`);
  }
  pe.imports.entries.forEach((mod, index) => {
    const dll = escapeHtml(mod.dll || "(unknown DLL)");
    const linkedModule = findLinkedModuleForImport(pe, index);
    const linkedImport = findLinkedImportDescriptor(linkedModule, index);
    const moduleNote = renderImportLibraryInfoNote(mod.dll);
    out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>${dll}</b> - ${mod.functions?.length || 0} function(s)</summary>`);
    out.push(`<dl style="margin-top:.35rem">`);
    if (moduleNote) out.push(renderDefinitionRow("DLL-name note", moduleNote));
    out.push(renderDefinitionRow("OriginalFirstThunk", hex(mod.originalFirstThunkRva >>> 0, 8), "PE format: RVA of the Import Lookup Table (INT/ILT)."));
    out.push(renderDefinitionRow("OriginalFirstThunk section", describeSectionForRva(pe, mod.originalFirstThunkRva), "Section containing the Import Lookup Table RVA."));
    out.push(renderDefinitionRow("FirstThunk", hex(mod.firstThunkRva >>> 0, 8), "PE format: RVA of the Import Address Table (IAT) that the loader patches with resolved addresses."));
    out.push(renderDefinitionRow("FirstThunk section", describeSectionForRva(pe, mod.firstThunkRva), "Section containing the IAT slots for this descriptor."));
    out.push(renderDefinitionRow("Lookup source", renderLookupSource(mod.lookupSource), "Whether names came from OriginalFirstThunk/INT or from FirstThunk/IAT as a fallback."));
    out.push(renderDefinitionRow("TimeDateStamp", hex(mod.timeDateStamp >>> 0, 8), "Raw import-descriptor TimeDateStamp field. Non-zero values often mean binding-related metadata, but the field is producer-controlled."));
    out.push(renderDefinitionRow("ForwarderChain", hex(mod.forwarderChain >>> 0, 8), "Raw import-descriptor ForwarderChain field."));
    out.push(renderDefinitionRow("IAT directory relation", renderIatRelation(linkedImport?.iatDirectoryRelation), "Whether FirstThunk starts inside the IMAGE_DIRECTORY_ENTRY_IAT range."));
    out.push(renderDefinitionRow("Binding", renderBinding(linkedImport?.bindingRelation), "Whether this module matched a BOUND_IMPORT entry or only carries raw timestamp metadata."));
    out.push(renderFindingRows(filterFindings(linkedModule, [
      "bound-match",
      "int-lookup",
      "eager-iat-covered",
      "iat-fallback",
      "timestamp-without-bound-import",
      "iat-fallback-with-timestamp",
      "eager-and-delay",
      "eager-iat-outside-directory"
    ])));
    out.push(`</dl>`);
    if (mod.functions?.length) {
      out.push(renderImportFunctionTable(
        mod.functions,
        `eager-import-${index}`,
        mod.firstThunkRva,
        counts,
        entrySize
      ));
    }
    out.push(`</details>`);
  });
  out.push(renderPeSectionEnd());
};

export const renderImportsPanel = (pe: PeWindowsParseResult): string => {
  const out: string[] = [];
  renderImportsContent(pe, out);
  return out.join("");
};

export function renderImports(pe: PeWindowsParseResult, out: string[]): void {
  out.push(renderImportsPanel(pe));
}

export function renderBoundImports(pe: PeWindowsParseResult, out: string[]): void {
  if (!pe.boundImports || (!pe.boundImports.entries.length && !pe.boundImports.warning)) return;
  out.push(
    renderPeSectionStart(
      "Bound imports",
      `${pe.boundImports.entries.length} module${pe.boundImports.entries.length === 1 ? "" : "s"}`
    )
  );
  out.push(`<div class="smallNote">BOUND_IMPORT is optional prebinding metadata. It does not replace the normal import table; it supplements it with imported-module timestamps and optional forwarder references.</div>`);
  if (pe.boundImports.warning) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${escapeHtml(pe.boundImports.warning)}</div>`);
  }
  if (pe.boundImports.entries.length) {
    out.push(`<div class="tableWrap"><table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Module</th><th>TimeDateStamp</th><th>ForwarderRefs</th><th>Validated</th><th>Warnings / notes</th></tr></thead><tbody>`);
    pe.boundImports.entries.forEach((entry, index) => {
      const linkedModule = findLinkedModuleForBoundImport(pe, index);
      const forwarderLabel = entry.forwarderRefs?.length
        ? `${entry.NumberOfModuleForwarderRefs}: ${escapeHtml(entry.forwarderRefs.map(ref => ref.name || "(unnamed)").join(", "))}`
        : String(entry.NumberOfModuleForwarderRefs);
      const findings = filterFindings(linkedModule, ["bound-match", "bound-without-import"]);
      out.push(`<tr><td>${index + 1}</td><td>${renderImportLibraryNameWithInfo(entry.name || "")}</td><td>${hex(entry.TimeDateStamp >>> 0, 8)}</td><td>${forwarderLabel}</td><td>${renderFindingSummary(findings, "confirmed")}</td><td>${renderFindingSummary(findings, "warning")}${renderFindingSummary(findings, "info")}</td></tr>`);
    });
    out.push(`</tbody></table></div>`);
  }
  out.push(renderPeSectionEnd());
}

const renderDelayImportsContent = (pe: PeWindowsParseResult, out: string[]): void => {
  if (!pe.delayImports || (!pe.delayImports.entries.length && !pe.delayImports.warning)) return;
  const counts = directIatReferenceCounts(pe);
  const entrySize = directIatEntrySize(pe);
  out.push(
    renderPeSectionStart(
      "Delay-load imports",
      `${pe.delayImports.entries.length} module${pe.delayImports.entries.length === 1 ? "" : "s"}`,
      PE_DELAY_IMPORTS_PANEL_ID
    )
  );
  out.push(`<div class="smallNote">Delay-load descriptors describe imports that are resolved on first use instead of during process startup. Modern Windows images sometimes protect delay-load IATs with Load Config GuardFlags and a dedicated .didat section.</div>`);
  if (pe.delayImports.warning) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${escapeHtml(pe.delayImports.warning)}</div>`);
  }
  pe.delayImports.entries.forEach((entry, index) => {
    const dll = escapeHtml(entry.name || "(unknown DLL)");
    const linkedModule = findLinkedModuleForDelayImport(pe, index);
    const linkedDelayImport = findLinkedDelayImportDescriptor(linkedModule, index);
    const moduleNote = renderImportLibraryInfoNote(entry.name);
    out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>${dll}</b> - ${entry.functions?.length || 0} function(s)</summary>`);
    out.push(`<dl style="margin-top:.35rem">`);
    if (moduleNote) out.push(renderDefinitionRow("DLL-name note", moduleNote));
    out.push(renderDefinitionRow("Attributes", hex(entry.Attributes >>> 0, 8), "MSVC delayimp.h documents bit 0 as dlattrRva for VC7+ RVA-based descriptors, while the PE format page separately says the field should be zero."));
    out.push(renderDefinitionRow("ModuleHandleRVA", hex(entry.ModuleHandleRVA >>> 0, 8), "Delay-load module-handle slot."));
    out.push(renderDefinitionRow("ModuleHandle section", describeSectionForRva(pe, entry.ModuleHandleRVA), "Section containing the delay-load module-handle slot."));
    out.push(renderDefinitionRow("ImportAddressTableRVA", hex(entry.ImportAddressTableRVA >>> 0, 8), "Delay-load IAT used by the helper."));
    out.push(renderDefinitionRow("Delay IAT section", renderDelaySectionContext(pe, entry.ImportAddressTableRVA), "Section containing the delay-load Import Address Table."));
    out.push(renderDefinitionRow("ImportNameTableRVA", hex(entry.ImportNameTableRVA >>> 0, 8), "Delay-load name/ordinal thunk table."));
    out.push(renderDefinitionRow("ImportNameTable section", describeSectionForRva(pe, entry.ImportNameTableRVA), "Section containing the delay-load name/ordinal lookup table."));
    out.push(renderDefinitionRow("BoundImportAddressTableRVA", hex(entry.BoundImportAddressTableRVA >>> 0, 8), "Optional delay-load bound-IAT pointer."));
    out.push(renderDefinitionRow("Bound delay IAT section", describeSectionForRva(pe, entry.BoundImportAddressTableRVA), "Section containing the optional bound delay-load IAT."));
    out.push(renderDefinitionRow("UnloadInformationTableRVA", hex(entry.UnloadInformationTableRVA >>> 0, 8), "Optional delay-load unload table."));
    out.push(renderDefinitionRow("Unload table section", describeSectionForRva(pe, entry.UnloadInformationTableRVA), "Section containing the optional unload table."));
    out.push(renderDefinitionRow("TimeDateStamp", hex(entry.TimeDateStamp >>> 0, 8), "Raw delay-import timestamp field."));
    out.push(renderDefinitionRow("Also imported eagerly", linkedModule?.imports.length ? "Yes" : "No", "Whether the same DLL also appears in the normal import table."));
    out.push(renderDefinitionRow("IAT directory relation", renderIatRelation(linkedDelayImport?.iatDirectoryRelation), "Whether ImportAddressTableRVA starts inside IMAGE_DIRECTORY_ENTRY_IAT."));
    out.push(renderDefinitionRow("Load Config delay-IAT flags", renderDelayGuardContext(pe), "Cross-checks protected delay-load IAT layout against Load Config GuardFlags."));
    out.push(renderFindingRows(filterFindings(linkedModule, [
      "delay-iat-covered",
      "protected-delay-iat-own-section",
      "protected-delay-iat-separate-section",
      "delay-iat-own-section-mismatch",
      "delay-iat-outside-directory",
      "eager-and-delay"
    ])));
    out.push(`</dl>`);
    if (entry.functions?.length) {
      out.push(renderImportFunctionTable(
        entry.functions,
        `delay-import-${index}`,
        entry.ImportAddressTableRVA,
        counts,
        entrySize
      ));
    }
    out.push(`</details>`);
  });
  out.push(renderPeSectionEnd());
};

export const renderDelayImportsPanel = (pe: PeWindowsParseResult): string => {
  const out: string[] = [];
  renderDelayImportsContent(pe, out);
  return out.join("");
};

export function renderDelayImports(pe: PeWindowsParseResult, out: string[]): void {
  out.push(renderDelayImportsPanel(pe));
}

export function renderIat(pe: PeWindowsParseResult, out: string[]): void {
  const inferredEagerIat = pe.importLinking?.inferredEagerIat ?? null;
  if (!pe.iat && !inferredEagerIat) return;
  const eagerRelations = pe.importLinking?.modules.flatMap(module =>
    module.imports.map(linkedImport => linkedImport.iatDirectoryRelation)
  ) ?? [];
  const delayRelations = pe.importLinking?.modules.flatMap(module =>
    module.delayImports.map(linkedImport => linkedImport.iatDirectoryRelation)
  ) ?? [];
  const declaredVsInferredFindings = filterStandaloneFindings(pe.importLinking?.findings, [
    "declared-iat-absent-inferred-eager",
    "declared-iat-exact-match",
    "declared-iat-covers-inferred-eager",
    "declared-iat-misses-inferred-eager"
  ]);
  out.push(
    renderPeSectionStart(
      "Import Address Tables (IAT)",
      `${pe.iat ? "declared" : "undeclared"}, ${inferredEagerIat?.ranges.length ?? 0} inferred range${(inferredEagerIat?.ranges.length ?? 0) === 1 ? "" : "s"}`
    )
  );
  out.push(`<div class="smallNote">The PE optional header can declare one main IMAGE_DIRECTORY_ENTRY_IAT range, while each eager import descriptor also carries its own FirstThunk RVA. This view keeps those two ideas separate: the declared main IAT range from the optional header, and best-effort eager IAT ranges inferred from FirstThunk values.</div>`);
  if (pe.iat?.warnings?.length) {
    out.push(`<ul class="smallNote">`);
    pe.iat.warnings.forEach(warning => out.push(`<li>${escapeHtml(warning)}</li>`));
    out.push(`</ul>`);
  }
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Declared IAT directory", pe.iat ? "Present" : "Absent", "Whether the optional header includes IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(renderDefinitionRow("Declared main IAT RVA", pe.iat ? hex(pe.iat.rva, 8) : "-", "RVA from IMAGE_DIRECTORY_ENTRY_IAT in the optional header."));
  out.push(renderDefinitionRow("Declared main IAT size", pe.iat ? humanSize(pe.iat.size) : "-", "Size from IMAGE_DIRECTORY_ENTRY_IAT in the optional header."));
  out.push(renderDefinitionRow("Declared main IAT range", pe.iat ? `${hex(pe.iat.rva, 8)} - ${hex((pe.iat.rva + pe.iat.size) >>> 0, 8)}` : "-", "Half-open RVA range declared by IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(renderDefinitionRow("Declared main IAT section", pe.iat ? describeSectionForRva(pe, pe.iat.rva) : "-", "Section containing the declared IMAGE_DIRECTORY_ENTRY_IAT RVA."));
  out.push(renderDefinitionRow("Inferred eager IAT ranges", inferredEagerIat ? String(inferredEagerIat.ranges.length) : "0", "Best-effort eager IAT ranges inferred from FirstThunk values in the normal import descriptors."));
  out.push(renderDefinitionRow("Inferred eager IAT aggregate", inferredEagerIat ? `${hex(inferredEagerIat.aggregateStartRva, 8)} - ${hex(inferredEagerIat.aggregateEndRva, 8)}` : "-", "Half-open aggregate span that covers all inferred eager IAT ranges."));
  out.push(renderDefinitionRow("Inferred eager IAT size", inferredEagerIat ? humanSize(inferredEagerIat.aggregateSize) : "-", "Aggregate size covered by inferred eager IAT ranges."));
  out.push(renderDefinitionRow("Inferred thunk entry size", inferredEagerIat ? `${inferredEagerIat.thunkEntrySize} bytes` : "-", "PE32 eager IAT thunks are 4 bytes; PE32+ eager IAT thunks are 8 bytes."));
  out.push(renderDefinitionRow("Declared vs inferred eager IAT", inferredEagerIat ? renderDeclaredIatRelation(inferredEagerIat.relationToDeclared) : "-", "Compares IMAGE_DIRECTORY_ENTRY_IAT from the optional header against eager IAT ranges inferred from FirstThunk values."));
  out.push(renderFindingRows(declaredVsInferredFindings));
  out.push(renderDefinitionRow("Eager imports inside", String(countRelation(eagerRelations, "covered")), "Normal import descriptors whose FirstThunk starts inside IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(renderDefinitionRow("Eager imports outside", String(countRelation(eagerRelations, "outside-directory")), "Normal import descriptors whose FirstThunk starts outside IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(renderDefinitionRow("Eager imports with no declared IAT", String(countRelation(eagerRelations, "missing-directory")), "Normal import descriptors whose FirstThunk exists but IMAGE_DIRECTORY_ENTRY_IAT is absent."));
  out.push(renderDefinitionRow("Delay-load IATs inside", String(countRelation(delayRelations, "covered")), "Delay-load descriptors whose ImportAddressTableRVA starts inside IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(renderDefinitionRow("Delay-load IATs outside", String(countRelation(delayRelations, "outside-directory")), "Delay-load descriptors whose ImportAddressTableRVA starts outside IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(renderDefinitionRow("Delay-load IATs with no declared IAT", String(countRelation(delayRelations, "missing-directory")), "Delay-load descriptors whose ImportAddressTableRVA exists but IMAGE_DIRECTORY_ENTRY_IAT is absent."));
  out.push(renderDefinitionRow("Protected delay-load modules", String(countModulesWithFindingCodes(pe.importLinking?.modules ?? [], ["protected-delay-iat-own-section", "protected-delay-iat-separate-section"])), "Modules whose outside-main-IAT delay-load layout was confirmed by Load Config GuardFlags and section placement."));
  out.push(`</dl>`);
  if (inferredEagerIat) {
    out.push(`<div class="tableWrap"><table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Range</th><th>Size</th><th>Section</th><th>Descriptors</th><th>Modules</th></tr></thead><tbody>`);
    inferredEagerIat.ranges.forEach((range, rangeIndex) => {
      out.push(`<tr><td>${rangeIndex + 1}</td><td>${hex(range.startRva, 8)} - ${hex(range.endRva, 8)}</td><td>${humanSize(range.size)}</td><td>${describeSectionForRva(pe, range.startRva)}</td><td>${range.descriptorCount}</td><td>${renderImportNamesForIndices(pe, range.importIndices)}</td></tr>`);
    });
    out.push(`</tbody></table></div>`);
  }
  out.push(renderPeSectionEnd());
}
