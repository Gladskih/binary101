"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import {
  isPeRomParseResult,
  isPeWindowsParseResult,
  type PeParseResult,
  type PeWindowsParseResult
} from "../../analyzers/pe/index.js";
import { renderPeDiagnosticBody, renderPeDiagnostics } from "./diagnostics.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

type PeRelocSection = NonNullable<PeWindowsParseResult["reloc"]>;
type PeBoundImportsSection = NonNullable<PeWindowsParseResult["boundImports"]>;
type PeDelayImportsSection = NonNullable<PeWindowsParseResult["delayImports"]>;

// Microsoft PE format, "Section Flags":
// IMAGE_SCN_MEM_EXECUTE marks executable section contents.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
// MSVC delayimp.h / "Understand the delay load helper function":
// dlattrRva marks VC7+ delay descriptors whose fields are RVAs.
// https://learn.microsoft.com/en-us/cpp/build/reference/understanding-the-helper-function
const DELAY_IMPORT_ATTRIBUTE_DLATTR_RVA = 0x1;

const getEntrypointSanityIssue = (pe: PeParseResult): string | null => {
  const entrypointRva = pe.opt?.AddressOfEntryPoint ? (pe.opt.AddressOfEntryPoint >>> 0) : 0;
  const sections = Array.isArray(pe.sections) ? pe.sections : [];
  if (!entrypointRva || !sections.length) return null;
  const entrySection = sections.find(section => {
    const start = section.virtualAddress >>> 0;
    const size = (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);
    const end = start + size;
    return entrypointRva >= start && entrypointRva < end;
  });
  if (!entrySection) {
    return `AddressOfEntryPoint points outside any section (RVA ${hex(entrypointRva, 8)}).`;
  }
  return (entrySection.characteristics & IMAGE_SCN_MEM_EXECUTE) === 0
    ? `Entry point is in a non-executable section (${entrySection.name || "(unnamed)"}; missing IMAGE_SCN_MEM_EXECUTE).`
    : null;
};

const singleIssue = (issue: string | null | undefined): string[] => issue ? [issue] : [];

export const getPeSanityIssues = (pe: PeParseResult): string[] => [
  ...(pe.warnings || []),
  ...(
    pe.imageSizeMismatch && !isPeRomParseResult(pe)
      ? ["SizeOfImage does not match section layout."]
      : []
  ),
  ...(isPeWindowsParseResult(pe) && pe.debug?.warning ? [pe.debug.warning] : []),
  ...singleIssue(getEntrypointSanityIssue(pe))
];

const renderDelayImportAttributes = (attributes: number): string => {
  const normalized = attributes >>> 0;
  const unknownBits = normalized & ~DELAY_IMPORT_ATTRIBUTE_DLATTR_RVA;
  const notes = (normalized & DELAY_IMPORT_ATTRIBUTE_DLATTR_RVA) !== 0
    ? [
        "dlattrRva set: MSVC delayimp.h / \"Understand the delay load helper function\" say this marks VC7+ delay descriptors whose fields are RVAs.",
        "Microsoft's PE format page separately says the Delay-Load Attributes field must be zero, so the official docs conflict."
      ]
    : normalized === 0
      ? [
          "Value 0 matches the PE format page, which says the Delay-Load Attributes field must be zero.",
          "MSVC delayimp.h / \"Understand the delay load helper function\" also define bit 0 as dlattrRva for VC7+ RVA-based descriptors, so Microsoft's own sources disagree here."
        ]
    : [
        "dlattrRva is clear, but the value is not zero.",
        "The PE format page says this field should be zero, while MSVC delayimp.h / \"Understand the delay load helper function\" reserve bit 0 for dlattrRva."
      ];
  if (unknownBits !== 0) {
    notes.push(`Unknown or undocumented attribute bits remain set: ${hex(unknownBits, 8)}.`);
  }
  return `${hex(normalized, 8)}<div class="smallNote">${notes.map(escapeHtml).join("<br/>")}</div>`;
};

export function renderReloc(reloc: PeRelocSection, out: string[]): void {
  out.push(
    renderPeSectionStart(
      "Base relocations",
      `${reloc.totalEntries ?? 0} entr${(reloc.totalEntries ?? 0) === 1 ? "y" : "ies"}`
    )
  );
  out.push(`<div class="smallNote">Relocation blocks are used when the image cannot be loaded at its preferred base address.</div>`);
  if (reloc.warnings?.length) {
    out.push(renderPeDiagnostics("Base relocation warnings", reloc.warnings));
  }
  out.push(`<dl>`);
  out.push(`<dt>Total entries</dt><dd>${reloc.totalEntries ?? 0}</dd>`);
  out.push(`</dl>`);
  if (reloc.blocks?.length) {
    out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Page RVA</th><th>Block size</th><th>Entries</th></tr></thead><tbody>`);
    reloc.blocks.forEach((block, index) => {
      out.push(`<tr><td>${index + 1}</td><td>${hex(block.pageRva, 8)}</td><td>${humanSize(block.size)}</td><td>${block.count}</td></tr>`);
    });
    out.push(`</tbody></table>`);
  }
  out.push(renderPeSectionEnd());
}

export function renderBoundImports(bi: PeBoundImportsSection, out: string[]): void {
  if (!bi.entries?.length && !bi.warning) return;
  out.push(renderPeSectionStart("Bound imports"));
  if (bi.warning) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${escapeHtml(bi.warning)}</div>`);
  }
  if (bi.entries?.length) {
    out.push(
      `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show bound imports (${bi.entries.length})</summary>`
    );
    out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Module</th><th>TimeDateStamp</th><th>ForwarderRefs</th></tr></thead><tbody>`);
    bi.entries.forEach((e, index) => {
      const forwarderLabel = e.forwarderRefs?.length
        ? `${e.NumberOfModuleForwarderRefs}: ${escapeHtml(e.forwarderRefs.map(ref => ref.name || "(unnamed)").join(", "))}`
        : String(e.NumberOfModuleForwarderRefs);
      out.push(
        `<tr><td>${index + 1}</td><td>${escapeHtml(e.name || "")}</td><td>${hex(e.TimeDateStamp, 8)}</td><td>${forwarderLabel}</td></tr>`
      );
    });
    out.push(`</tbody></table></details>`);
  }
  out.push(renderPeSectionEnd());
}

export function renderDelayImports(di: PeDelayImportsSection, out: string[]): void {
  if (!di.entries?.length && !di.warning) return;
  out.push(renderPeSectionStart("Delay-load imports"));
  if (di.warning) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${escapeHtml(di.warning)}</div>`);
  }
  for (const entry of di.entries) {
    const dll = escapeHtml(entry.name || "(unknown DLL)");
    const fnCount = entry.functions?.length || 0;
    out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>${dll}</b> \u2014 ${fnCount} function(s)</summary>`);
    out.push(`<dl style="margin-top:.35rem">`);
    out.push(`<dt>Attributes</dt><dd>${renderDelayImportAttributes(entry.Attributes)}</dd>`);
    out.push(`<dt>ModuleHandleRVA</dt><dd>${hex(entry.ModuleHandleRVA >>> 0, 8)}</dd>`);
    out.push(`<dt>ImportAddressTableRVA</dt><dd>${hex(entry.ImportAddressTableRVA >>> 0, 8)}</dd>`);
    out.push(`<dt>ImportNameTableRVA</dt><dd>${hex(entry.ImportNameTableRVA >>> 0, 8)}</dd>`);
    out.push(`<dt>BoundImportAddressTableRVA</dt><dd>${hex(entry.BoundImportAddressTableRVA >>> 0, 8)}</dd>`);
    out.push(`<dt>UnloadInformationTableRVA</dt><dd>${hex(entry.UnloadInformationTableRVA >>> 0, 8)}</dd>`);
    out.push(`<dt>TimeDateStamp</dt><dd>${hex(entry.TimeDateStamp >>> 0, 8)}</dd>`);
    out.push(`</dl>`);
    if (fnCount) {
      out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Hint</th><th>Name / Ordinal</th></tr></thead><tbody>`);
      entry.functions.forEach((fn, index) => {
        const hint = fn.hint != null ? String(fn.hint) : "-";
        const nm = fn.name ? escapeHtml(fn.name) : fn.ordinal != null ? "ORD " + fn.ordinal : "-";
        out.push(`<tr><td>${index + 1}</td><td>${hint}</td><td>${nm}</td></tr>`);
      });
      out.push(`</tbody></table>`);
    }
    out.push(`</details>`);
  }
  out.push(renderPeSectionEnd());
}

export function renderSanity(pe: PeParseResult, out: string[]): void {
  const issues = getPeSanityIssues(pe);
  if (!issues.length) return;
  out.push(renderPeSectionStart("Sanity", `${issues.length} finding${issues.length === 1 ? "" : "s"}`));
  out.push(renderPeDiagnosticBody(issues));
  out.push(renderPeSectionEnd());
}
