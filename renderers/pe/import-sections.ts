"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { dd, safe } from "../../html-utils.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import {
  countModulesWithFindingCodes,
  countRelation,
  describeSectionForRva,
  filterFindings,
  findLinkedDelayImportDescriptor,
  findLinkedModuleForBoundImport,
  findLinkedModuleForDelayImport,
  findLinkedModuleForImport,
  findLinkedImportDescriptor,
  renderBinding,
  renderDelayGuardContext,
  renderDelaySectionContext,
  renderFindingRows,
  renderFindingSummary,
  renderIatRelation
  ,
  renderLookupSource
} from "./import-linking-format.js";

export { renderImportLinking } from "./import-linking-section.js";

export function renderImports(pe: PeParseResult, out: string[]): void {
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

export function renderBoundImports(pe: PeParseResult, out: string[]): void {
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

export function renderDelayImports(pe: PeParseResult, out: string[]): void {
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

export function renderIat(pe: PeParseResult, out: string[]): void {
  if (!pe.iat) return;
  const eagerRelations = pe.importLinking?.modules.flatMap(module =>
    module.imports.map(linkedImport => linkedImport.iatDirectoryRelation)
  ) ?? [];
  const delayRelations = pe.importLinking?.modules.flatMap(module =>
    module.delayImports.map(linkedImport => linkedImport.iatDirectoryRelation)
  ) ?? [];
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Import Address Table (IAT)</h4><div class="smallNote">IMAGE_DIRECTORY_ENTRY_IAT gives one RVA/size range for the main runtime import-address slots. Delay-load descriptors may legally keep their own IAT ranges elsewhere when the producer uses a protected delay-load layout documented by Microsoft.</div>`);
  if (pe.iat.warnings?.length) {
    out.push(`<ul class="smallNote">`);
    pe.iat.warnings.forEach(warning => out.push(`<li>${safe(warning)}</li>`));
    out.push(`</ul>`);
  }
  out.push(`<dl>`);
  out.push(dd("RVA", hex(pe.iat.rva, 8), "RVA of the main IAT directory."));
  out.push(dd("Size", humanSize(pe.iat.size), "Total size of the main IAT directory in bytes."));
  out.push(dd("Range", `${hex(pe.iat.rva, 8)} - ${hex((pe.iat.rva + pe.iat.size) >>> 0, 8)}`, "Half-open RVA range covered by IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(dd("Main IAT section", describeSectionForRva(pe, pe.iat.rva), "Section containing the main IMAGE_DIRECTORY_ENTRY_IAT RVA."));
  out.push(dd("Eager imports inside", String(countRelation(eagerRelations, "covered")), "Normal import descriptors whose FirstThunk starts inside IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(dd("Eager imports outside", String(countRelation(eagerRelations, "outside-directory")), "Normal import descriptors whose FirstThunk starts outside IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(dd("Delay-load IATs inside", String(countRelation(delayRelations, "covered")), "Delay-load descriptors whose ImportAddressTableRVA starts inside IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(dd("Delay-load IATs outside", String(countRelation(delayRelations, "outside-directory")), "Delay-load descriptors whose ImportAddressTableRVA starts outside IMAGE_DIRECTORY_ENTRY_IAT."));
  out.push(dd("Protected delay-load modules", String(countModulesWithFindingCodes(pe.importLinking?.modules ?? [], ["protected-delay-iat-own-section", "protected-delay-iat-separate-section"])), "Modules whose outside-main-IAT delay-load layout was confirmed by Load Config GuardFlags and section placement."));
  out.push(`</dl></section>`);
}
