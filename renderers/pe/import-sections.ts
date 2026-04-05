"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { dd, safe } from "../../html-utils.js";
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
  renderIatRelation
  ,
  renderLookupSource
} from "./import-linking-format.js";

export { renderImportLinking } from "./import-linking-section.js";

export function renderImports(pe: PeWindowsParseResult, out: string[]): void {
  if (!pe.imports.entries.length && !pe.imports.warning) return;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Import table</h4><div class="smallNote">Each IMAGE_IMPORT_DESCRIPTOR names one DLL and points to two tables: OriginalFirstThunk normally gives the lookup names, while FirstThunk gives the runtime IAT slots that the loader patches.</div>`);
  if (pe.imports.warning) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${safe(pe.imports.warning)}</div>`);
  }
  pe.imports.entries.forEach((mod, index) => {
    const dll = safe(mod.dll || "(unknown DLL)");
    const linkedModule = findLinkedModuleForImport(pe, index);
    const linkedImport = findLinkedImportDescriptor(linkedModule, index);
    out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>${dll}</b> - ${mod.functions?.length || 0} function(s)</summary>`);
    out.push(`<dl style="margin-top:.35rem">`);
    out.push(dd("OriginalFirstThunk", hex(mod.originalFirstThunkRva >>> 0, 8), "PE format: RVA of the Import Lookup Table (INT/ILT)."));
    out.push(dd("OriginalFirstThunk section", describeSectionForRva(pe, mod.originalFirstThunkRva), "Section containing the Import Lookup Table RVA."));
    out.push(dd("FirstThunk", hex(mod.firstThunkRva >>> 0, 8), "PE format: RVA of the Import Address Table (IAT) that the loader patches with resolved addresses."));
    out.push(dd("FirstThunk section", describeSectionForRva(pe, mod.firstThunkRva), "Section containing the IAT slots for this descriptor."));
    out.push(dd("Lookup source", renderLookupSource(mod.lookupSource), "Whether names came from OriginalFirstThunk/INT or from FirstThunk/IAT as a fallback."));
    out.push(dd("TimeDateStamp", hex(mod.timeDateStamp >>> 0, 8), "Raw import-descriptor TimeDateStamp field. Non-zero values often mean binding-related metadata, but the field is producer-controlled."));
    out.push(dd("ForwarderChain", hex(mod.forwarderChain >>> 0, 8), "Raw import-descriptor ForwarderChain field."));
    out.push(dd("IAT directory relation", renderIatRelation(linkedImport?.iatDirectoryRelation), "Whether FirstThunk starts inside the IMAGE_DIRECTORY_ENTRY_IAT range."));
    out.push(dd("Binding", renderBinding(linkedImport?.bindingRelation), "Whether this module matched a BOUND_IMPORT entry or only carries raw timestamp metadata."));
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
      out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Hint</th><th>Name / Ordinal</th></tr></thead><tbody>`);
      mod.functions.forEach((fn, functionIndex) => {
        const hint = fn.hint != null ? String(fn.hint) : "-";
        const name = fn.name ? safe(fn.name) : fn.ordinal != null ? `ORD ${fn.ordinal}` : "-";
        out.push(`<tr><td>${functionIndex + 1}</td><td>${hint}</td><td>${name}</td></tr>`);
      });
      out.push(`</tbody></table>`);
    }
    out.push(`</details>`);
  });
  out.push(`</section>`);
}

export function renderBoundImports(pe: PeWindowsParseResult, out: string[]): void {
  if (!pe.boundImports?.entries.length) return;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Bound imports</h4><div class="smallNote">BOUND_IMPORT is optional prebinding metadata. It does not replace the normal import table; it supplements it with imported-module timestamps and optional forwarder references.</div>`);
  if (pe.boundImports.warning) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${safe(pe.boundImports.warning)}</div>`);
  }
  out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show bound imports (${pe.boundImports.entries.length})</summary>`);
  out.push(`<div class="tableWrap"><table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Module</th><th>TimeDateStamp</th><th>ForwarderRefs</th><th>Validated</th><th>Warnings / notes</th></tr></thead><tbody>`);
  pe.boundImports.entries.forEach((entry, index) => {
    const linkedModule = findLinkedModuleForBoundImport(pe, index);
    const forwarderLabel = entry.forwarderRefs?.length
      ? `${entry.NumberOfModuleForwarderRefs}: ${safe(entry.forwarderRefs.map(ref => ref.name || "(unnamed)").join(", "))}`
      : String(entry.NumberOfModuleForwarderRefs);
    const findings = filterFindings(linkedModule, ["bound-match", "bound-without-import"]);
    out.push(`<tr><td>${index + 1}</td><td>${safe(entry.name || "")}</td><td>${hex(entry.TimeDateStamp >>> 0, 8)}</td><td>${forwarderLabel}</td><td>${renderFindingSummary(findings, "confirmed")}</td><td>${renderFindingSummary(findings, "warning")}${renderFindingSummary(findings, "info")}</td></tr>`);
  });
  out.push(`</tbody></table></div></details></section>`);
}

export function renderDelayImports(pe: PeWindowsParseResult, out: string[]): void {
  if (!pe.delayImports?.entries.length) return;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Delay-load imports</h4><div class="smallNote">Delay-load descriptors describe imports that are resolved on first use instead of during process startup. Modern Windows images sometimes protect delay-load IATs with Load Config GuardFlags and a dedicated .didat section.</div>`);
  if (pe.delayImports.warning) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${safe(pe.delayImports.warning)}</div>`);
  }
  pe.delayImports.entries.forEach((entry, index) => {
    const dll = safe(entry.name || "(unknown DLL)");
    const linkedModule = findLinkedModuleForDelayImport(pe, index);
    const linkedDelayImport = findLinkedDelayImportDescriptor(linkedModule, index);
    out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>${dll}</b> - ${entry.functions?.length || 0} function(s)</summary>`);
    out.push(`<dl style="margin-top:.35rem">`);
    out.push(dd("Attributes", hex(entry.Attributes >>> 0, 8), "MSVC delayimp.h documents bit 0 as dlattrRva for VC7+ RVA-based descriptors, while the PE format page separately says the field should be zero."));
    out.push(dd("ModuleHandleRVA", hex(entry.ModuleHandleRVA >>> 0, 8), "Delay-load module-handle slot."));
    out.push(dd("ModuleHandle section", describeSectionForRva(pe, entry.ModuleHandleRVA), "Section containing the delay-load module-handle slot."));
    out.push(dd("ImportAddressTableRVA", hex(entry.ImportAddressTableRVA >>> 0, 8), "Delay-load IAT used by the helper."));
    out.push(dd("Delay IAT section", renderDelaySectionContext(pe, entry.ImportAddressTableRVA), "Section containing the delay-load Import Address Table."));
    out.push(dd("ImportNameTableRVA", hex(entry.ImportNameTableRVA >>> 0, 8), "Delay-load name/ordinal thunk table."));
    out.push(dd("ImportNameTable section", describeSectionForRva(pe, entry.ImportNameTableRVA), "Section containing the delay-load name/ordinal lookup table."));
    out.push(dd("BoundImportAddressTableRVA", hex(entry.BoundImportAddressTableRVA >>> 0, 8), "Optional delay-load bound-IAT pointer."));
    out.push(dd("Bound delay IAT section", describeSectionForRva(pe, entry.BoundImportAddressTableRVA), "Section containing the optional bound delay-load IAT."));
    out.push(dd("UnloadInformationTableRVA", hex(entry.UnloadInformationTableRVA >>> 0, 8), "Optional delay-load unload table."));
    out.push(dd("Unload table section", describeSectionForRva(pe, entry.UnloadInformationTableRVA), "Section containing the optional unload table."));
    out.push(dd("TimeDateStamp", hex(entry.TimeDateStamp >>> 0, 8), "Raw delay-import timestamp field."));
    out.push(dd("Also imported eagerly", linkedModule?.imports.length ? "Yes" : "No", "Whether the same DLL also appears in the normal import table."));
    out.push(dd("IAT directory relation", renderIatRelation(linkedDelayImport?.iatDirectoryRelation), "Whether ImportAddressTableRVA starts inside IMAGE_DIRECTORY_ENTRY_IAT."));
    out.push(dd("Load Config delay-IAT flags", renderDelayGuardContext(pe), "Cross-checks protected delay-load IAT layout against Load Config GuardFlags."));
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
      out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Hint</th><th>Name / Ordinal</th></tr></thead><tbody>`);
      entry.functions.forEach((fn, functionIndex) => {
        const hint = fn.hint != null ? String(fn.hint) : "-";
        const name = fn.name ? safe(fn.name) : fn.ordinal != null ? `ORD ${fn.ordinal}` : "-";
        out.push(`<tr><td>${functionIndex + 1}</td><td>${hint}</td><td>${name}</td></tr>`);
      });
      out.push(`</tbody></table>`);
    }
    out.push(`</details>`);
  });
  out.push(`</section>`);
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
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Import Address Tables (IAT)</h4><div class="smallNote">The PE optional header can declare one main IMAGE_DIRECTORY_ENTRY_IAT range, while each eager import descriptor also carries its own FirstThunk RVA. This view keeps those two ideas separate: the declared main IAT range from the optional header, and best-effort eager IAT ranges inferred from FirstThunk values.</div>`);
  if (pe.iat?.warnings?.length) {
    out.push(`<ul class="smallNote">`);
    pe.iat.warnings.forEach(warning => out.push(`<li>${safe(warning)}</li>`));
    out.push(`</ul>`);
  }
  out.push(`<dl>`);
  out.push(dd("Declared IAT directory", pe.iat ? "Present" : "Absent", "Whether the optional header includes IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(dd("Declared main IAT RVA", pe.iat ? hex(pe.iat.rva, 8) : "-", "RVA from IMAGE_DIRECTORY_ENTRY_IAT in the optional header."));
  out.push(dd("Declared main IAT size", pe.iat ? humanSize(pe.iat.size) : "-", "Size from IMAGE_DIRECTORY_ENTRY_IAT in the optional header."));
  out.push(dd("Declared main IAT range", pe.iat ? `${hex(pe.iat.rva, 8)} - ${hex((pe.iat.rva + pe.iat.size) >>> 0, 8)}` : "-", "Half-open RVA range declared by IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(dd("Declared main IAT section", pe.iat ? describeSectionForRva(pe, pe.iat.rva) : "-", "Section containing the declared IMAGE_DIRECTORY_ENTRY_IAT RVA."));
  out.push(dd("Inferred eager IAT ranges", inferredEagerIat ? String(inferredEagerIat.ranges.length) : "0", "Best-effort eager IAT ranges inferred from FirstThunk values in the normal import descriptors."));
  out.push(dd("Inferred eager IAT aggregate", inferredEagerIat ? `${hex(inferredEagerIat.aggregateStartRva, 8)} - ${hex(inferredEagerIat.aggregateEndRva, 8)}` : "-", "Half-open aggregate span that covers all inferred eager IAT ranges."));
  out.push(dd("Inferred eager IAT size", inferredEagerIat ? humanSize(inferredEagerIat.aggregateSize) : "-", "Aggregate size covered by inferred eager IAT ranges."));
  out.push(dd("Inferred thunk entry size", inferredEagerIat ? `${inferredEagerIat.thunkEntrySize} bytes` : "-", "PE32 eager IAT thunks are 4 bytes; PE32+ eager IAT thunks are 8 bytes."));
  out.push(dd("Declared vs inferred eager IAT", inferredEagerIat ? renderDeclaredIatRelation(inferredEagerIat.relationToDeclared) : "-", "Compares IMAGE_DIRECTORY_ENTRY_IAT from the optional header against eager IAT ranges inferred from FirstThunk values."));
  out.push(renderFindingRows(declaredVsInferredFindings));
  out.push(dd("Eager imports inside", String(countRelation(eagerRelations, "covered")), "Normal import descriptors whose FirstThunk starts inside IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(dd("Eager imports outside", String(countRelation(eagerRelations, "outside-directory")), "Normal import descriptors whose FirstThunk starts outside IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(dd("Eager imports with no declared IAT", String(countRelation(eagerRelations, "missing-directory")), "Normal import descriptors whose FirstThunk exists but IMAGE_DIRECTORY_ENTRY_IAT is absent."));
  out.push(dd("Delay-load IATs inside", String(countRelation(delayRelations, "covered")), "Delay-load descriptors whose ImportAddressTableRVA starts inside IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(dd("Delay-load IATs outside", String(countRelation(delayRelations, "outside-directory")), "Delay-load descriptors whose ImportAddressTableRVA starts outside IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(dd("Delay-load IATs with no declared IAT", String(countRelation(delayRelations, "missing-directory")), "Delay-load descriptors whose ImportAddressTableRVA exists but IMAGE_DIRECTORY_ENTRY_IAT is absent."));
  out.push(dd("Protected delay-load modules", String(countModulesWithFindingCodes(pe.importLinking?.modules ?? [], ["protected-delay-iat-own-section", "protected-delay-iat-separate-section"])), "Modules whose outside-main-IAT delay-load layout was confirmed by Load Config GuardFlags and section placement."));
  out.push(`</dl>`);
  if (inferredEagerIat) {
    out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show inferred eager IAT ranges (${inferredEagerIat.ranges.length})</summary>`);
    out.push(`<div class="tableWrap"><table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Range</th><th>Size</th><th>Section</th><th>Descriptors</th><th>Modules</th></tr></thead><tbody>`);
    inferredEagerIat.ranges.forEach((range, rangeIndex) => {
      out.push(`<tr><td>${rangeIndex + 1}</td><td>${hex(range.startRva, 8)} - ${hex(range.endRva, 8)}</td><td>${humanSize(range.size)}</td><td>${describeSectionForRva(pe, range.startRva)}</td><td>${range.descriptorCount}</td><td>${renderImportNamesForIndices(pe, range.importIndices)}</td></tr>`);
    });
    out.push(`</tbody></table></div></details>`);
  }
  out.push(`</section>`);
}
