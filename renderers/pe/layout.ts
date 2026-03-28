"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { safe } from "../../html-utils.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

type PeRelocSection = NonNullable<PeParseResult["reloc"]>;
type PeExceptionSection = NonNullable<PeParseResult["exception"]>;
type PeBoundImportsSection = NonNullable<PeParseResult["boundImports"]>;
type PeDelayImportsSection = NonNullable<PeParseResult["delayImports"]>;

const IMAGE_SCN_MEM_EXECUTE = 0x20000000;

const computeRawImageEnd = (pe: PeParseResult): number =>
  (Array.isArray(pe.sections) ? pe.sections : []).reduce((maxEnd, section) => {
    const end = (section.pointerToRawData >>> 0) + (section.sizeOfRawData >>> 0);
    return Math.max(maxEnd, end);
  }, 0);

const clipOverlayRange = (
  overlayStart: number,
  overlayEnd: number,
  start: number,
  end: number
): { start: number; end: number } | null => {
  const clippedStart = Math.max(overlayStart, start);
  const clippedEnd = Math.min(overlayEnd, end);
  return clippedEnd > clippedStart ? { start: clippedStart, end: clippedEnd } : null;
};

const computeKnownOverlayCoverage = (pe: PeParseResult): number => {
  if (!Number.isFinite(pe.overlaySize) || pe.overlaySize <= 0) return 0;
  const overlayStart = computeRawImageEnd(pe);
  const overlayEnd = overlayStart + (pe.overlaySize >>> 0);
  const coveredRanges: Array<{ start: number; end: number }> = [];
  const securityDir = Array.isArray(pe.dirs) ? pe.dirs.find(dir => dir.name === "SECURITY") : null;
  if (securityDir?.size) {
    const clippedSecurityRange = clipOverlayRange(
      overlayStart,
      overlayEnd,
      securityDir.rva >>> 0,
      (securityDir.rva >>> 0) + (securityDir.size >>> 0)
    );
    if (clippedSecurityRange) coveredRanges.push(clippedSecurityRange);
  }
  for (const range of pe.debug?.rawDataRanges ?? []) {
    const clippedDebugRange = clipOverlayRange(overlayStart, overlayEnd, range.start, range.end);
    if (clippedDebugRange) coveredRanges.push(clippedDebugRange);
  }
  const mergedRanges = coveredRanges.sort((left, right) => left.start - right.start || left.end - right.end);
  let coveredBytes = 0;
  let currentStart = -1;
  let currentEnd = -1;
  for (const range of mergedRanges) {
    if (currentEnd < range.start) {
      coveredBytes += currentEnd > currentStart ? currentEnd - currentStart : 0;
      currentStart = range.start;
      currentEnd = range.end;
      continue;
    }
    currentEnd = Math.max(currentEnd, range.end);
  }
  coveredBytes += currentEnd > currentStart ? currentEnd - currentStart : 0;
  return coveredBytes;
};

export function renderReloc(reloc: PeRelocSection, out: string[]): void {
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Base relocations</h4>`);
  out.push(`<div class="smallNote">Relocation blocks are used when the image cannot be loaded at its preferred base address.</div>`);
  if (reloc.warnings?.length) {
    out.push(`<ul class="smallNote">`);
    reloc.warnings.forEach(warning => out.push(`<li>${safe(warning)}</li>`));
    out.push(`</ul>`);
  }
  out.push(`<dl>`);
  out.push(`<dt>Total entries</dt><dd>${reloc.totalEntries ?? 0}</dd>`);
  out.push(`</dl>`);
  if (reloc.blocks?.length) {
    out.push(
      `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show blocks (${reloc.blocks.length})</summary>`
    );
    out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Page RVA</th><th>Block size</th><th>Entries</th></tr></thead><tbody>`);
    reloc.blocks.forEach((block, index) => {
      out.push(`<tr><td>${index + 1}</td><td>${hex(block.pageRva, 8)}</td><td>${humanSize(block.size)}</td><td>${block.count}</td></tr>`);
    });
    out.push(`</tbody></table></details>`);
  }
  out.push(`</section>`);
}

export function renderException(ex: PeExceptionSection, out: string[]): void {
  const unwindLabel =
    ex.format === "arm64"
      ? "Unique unwind descriptions (.xdata or packed .pdata)"
      : "Unique UNWIND_INFO blocks";
  const handlerLabel =
    ex.format === "arm64"
      ? "Handlers present (ARM64 X bit)"
      : "Handlers present (EHANDLER/UHANDLER)";
  const chainedLabel = ex.format === "arm64" ? "Chained entries" : "Chained (CHAININFO)";
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Exception directory (.pdata)</h4>`);
  out.push(`<dl>`);
  out.push(`<dt>Functions (RUNTIME_FUNCTION entries)</dt><dd>${ex.functionCount ?? 0}</dd>`);
  out.push(`<dt>${unwindLabel}</dt><dd>${ex.uniqueUnwindInfoCount ?? 0}</dd>`);
  out.push(`<dt>${handlerLabel}</dt><dd>${ex.handlerUnwindInfoCount ?? 0}</dd>`);
  out.push(`<dt>${chainedLabel}</dt><dd>${ex.chainedUnwindInfoCount ?? 0}</dd>`);
  out.push(`<dt>Missing/invalid ranges</dt><dd>${ex.invalidEntryCount ?? 0}</dd>`);
  out.push(`</dl>`);
  if (ex.issues?.length) {
    out.push(`<ul class="smallNote">`);
    for (const issue of ex.issues) {
      out.push(`<li>${safe(issue)}</li>`);
    }
    out.push(`</ul>`);
  }
  out.push(`</section>`);
}

export function renderBoundImports(bi: PeBoundImportsSection, out: string[]): void {
  if (!bi.entries?.length) return;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Bound imports</h4>`);
  if (bi.warning) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${safe(bi.warning)}</div>`);
  }
  out.push(
    `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show bound imports (${bi.entries.length})</summary>`
  );
  out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Module</th><th>TimeDateStamp</th><th>ForwarderRefs</th></tr></thead><tbody>`);
  bi.entries.forEach((e, index) => {
    const forwarderLabel = e.forwarderRefs?.length
      ? `${e.NumberOfModuleForwarderRefs}: ${safe(e.forwarderRefs.map(ref => ref.name || "(unnamed)").join(", "))}`
      : String(e.NumberOfModuleForwarderRefs);
    out.push(
      `<tr><td>${index + 1}</td><td>${safe(e.name || "")}</td><td>${hex(e.TimeDateStamp, 8)}</td><td>${forwarderLabel}</td></tr>`
    );
  });
  out.push(`</tbody></table></details></section>`);
}

export function renderDelayImports(di: PeDelayImportsSection, out: string[]): void {
  if (!di.entries?.length) return;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Delay-load imports</h4>`);
  if (di.warning) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${safe(di.warning)}</div>`);
  }
  for (const entry of di.entries) {
    const dll = safe(entry.name || "(unknown DLL)");
    const fnCount = entry.functions?.length || 0;
    out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>${dll}</b> \u2014 ${fnCount} function(s)</summary>`);
    out.push(`<dl style="margin-top:.35rem">`);
    out.push(`<dt>Attributes</dt><dd>${hex(entry.Attributes >>> 0, 8)}</dd>`);
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
        const nm = fn.name ? safe(fn.name) : fn.ordinal != null ? "ORD " + fn.ordinal : "-";
        out.push(`<tr><td>${index + 1}</td><td>${hint}</td><td>${nm}</td></tr>`);
      });
      out.push(`</tbody></table>`);
    }
    out.push(`</details>`);
  }
  out.push(`</section>`);
}

export function renderSanity(pe: PeParseResult, out: string[]): void {
  const issues = [...(pe.warnings || [])];
  const unexplainedOverlaySize = Math.max(0, (pe.overlaySize >>> 0) - computeKnownOverlayCoverage(pe));
  if (unexplainedOverlaySize > 0) {
    issues.push(`Overlay after last section: ${humanSize(unexplainedOverlaySize)}.`);
  }
  if (pe.imageSizeMismatch) {
    issues.push("SizeOfImage does not match section layout.");
  }
  if (pe.debug?.warning) {
    issues.push(pe.debug.warning);
  }
  const entrypointRva = pe.opt?.AddressOfEntryPoint ? (pe.opt.AddressOfEntryPoint >>> 0) : 0;
  const sections = Array.isArray(pe.sections) ? pe.sections : [];
  if (entrypointRva && sections.length) {
    const entrySection = sections.find(section => {
      const start = section.virtualAddress >>> 0;
      const size = (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);
      const end = start + size;
      return entrypointRva >= start && entrypointRva < end;
    });
    if (!entrySection) {
      issues.push(`AddressOfEntryPoint points outside any section (RVA ${hex(entrypointRva, 8)}).`);
    } else if ((entrySection.characteristics & IMAGE_SCN_MEM_EXECUTE) === 0) {
      issues.push(
        `Entry point is in a non-executable section (${entrySection.name || "(unnamed)"}; missing IMAGE_SCN_MEM_EXECUTE).`
      );
    }
  }
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Sanity</h4>`);
  if (!issues.length) {
    out.push(`<div class="smallNote">No obvious structural issues detected.</div>`);
  } else {
    out.push(`<ul class="smallNote">`);
    for (const text of issues) {
      out.push(`<li>${safe(text)}</li>`);
    }
    out.push(`</ul>`);
  }
  out.push(`</section>`);
}
