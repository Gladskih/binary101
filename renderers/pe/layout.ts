import { renderCollectionStart, renderCollectionEnd } from "../counted-collection.js";
"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import { IMAGE_REL_BASED_ABSOLUTE } from "../../analyzers/pe/directories/reloc.js";
import {
  isPeRomParseResult,
  isPeWindowsParseResult,
  type PeParseResult,
  type PeWindowsParseResult
} from "../../analyzers/pe/index.js";
import { renderPeDiagnosticBody, renderPeDiagnostics } from "./diagnostics.js";
import { renderDelayImportAddressFields } from "./delay-import-addresses.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

type PeRelocSection = NonNullable<PeWindowsParseResult["reloc"]>;
type PeBoundImportsSection = NonNullable<PeWindowsParseResult["boundImports"]>;
type PeDelayImportsSection = NonNullable<PeWindowsParseResult["delayImports"]>;

// Microsoft PE format, "Section Flags":
// IMAGE_SCN_MEM_EXECUTE marks executable section contents.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
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
    ? `Entry point is in a non-executable section (${entrySection.name.value || "(unnamed)"}; missing IMAGE_SCN_MEM_EXECUTE).`
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

export const formatBaseRelocationSummary = (count: number): string =>
  `${count} parsed ${count === 1 ? "entry" : "entries"}`;

const renderBaseRelocationRows = (reloc: PeRelocSection, out: string[]): void => {
  out.push(`<p class="smallNote">The loader skips ABSOLUTE entries, which can pad a block. ` +
    `Parsed entry counts include them. HIGHADJ uses two WORDs and counts as one entry.</p>`);
  out.push(`<div class="tableWrap"><table class="table"><thead><tr>` +
    `<th scope="col" class="num">#</th><th scope="col">Page RVA</th>` +
    `<th scope="col" class="num">Block size</th><th scope="col" class="num">Parsed entries</th>` +
    `<th scope="col" class="num">ABSOLUTE (no-op)</th></tr></thead><tbody>`);
  reloc.blocks.forEach((block, index) => {
    const absoluteEntries = block.entries.reduce((count, entry) =>
      count + Number(entry.type === IMAGE_REL_BASED_ABSOLUTE), 0);
    out.push(`<tr><td class="num">${index + 1}</td><td>${hex(block.pageRva, 8)}</td>` +
      `<td class="num">${humanSize(block.size)}</td><td class="num">${block.count}</td>` +
      `<td class="num">${absoluteEntries}</td></tr>`);
  });
  out.push(`</tbody></table></div>`);
};

export function renderReloc(reloc: PeRelocSection, out: string[]): void {
  out.push(renderPeSectionStart("Base relocations", formatBaseRelocationSummary(reloc.totalEntries)));
  if (reloc.warnings?.length) {
    out.push(renderPeDiagnostics("Base relocation warnings", reloc.warnings));
  }
  if (reloc.blocks?.length) renderBaseRelocationRows(reloc, out);
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
      renderCollectionStart(`Show bound imports (${bi.entries.length})`, bi.entries.length)
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
    out.push(`</tbody></table>${renderCollectionEnd(bi.entries.length)}`);
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
    out.push(renderCollectionStart(`<b>${dll}</b> \u2014 ${fnCount} function(s)`, Math.max(1, fnCount)));
    out.push(`<dl style="margin-top:.35rem">`);
    out.push(renderDelayImportAddressFields(entry.Attributes));
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
    out.push(renderCollectionEnd(Math.max(1, fnCount)));
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
