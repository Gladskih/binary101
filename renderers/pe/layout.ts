"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { safe } from "../../html-utils.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

export function renderReloc(pe: PeParseResult, out: string[]): void {
  if (!pe.reloc) return;
  const reloc = pe.reloc;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Base relocations</h4>`);
  out.push(`<div class="smallNote">Relocation blocks are used when the image cannot be loaded at its preferred base address.</div>`);
  out.push(`<dl>`);
  out.push(`<dt>Total entries</dt><dd>${reloc.totalEntries ?? 0}</dd>`);
  out.push(`</dl>`);
  if (reloc.blocks?.length) {
    out.push(`<table class="table"><thead><tr><th>#</th><th>Page RVA</th><th>Block size</th><th>Entries</th></tr></thead><tbody>`);
    reloc.blocks.slice(0, 256).forEach((block, index) => {
      out.push(`<tr><td>${index + 1}</td><td>${hex(block.pageRva, 8)}</td><td>${humanSize(block.size)}</td><td>${block.count}</td></tr>`);
    });
    out.push(`</tbody></table>`);
  }
  out.push(`</section>`);
}

export function renderException(pe: PeParseResult, out: string[]): void {
  if (!pe.exception) return;
  const ex = pe.exception;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Exception directory (.pdata)</h4>`);
  out.push(`<dl>`);
  out.push(`<dt>Entry count</dt><dd>${ex.count ?? 0}</dd>`);
  out.push(`</dl>`);
  if (ex.sample?.length) {
    out.push(`<table class="table"><thead><tr><th>#</th><th>BeginAddress</th><th>EndAddress</th><th>UnwindInfoAddress</th></tr></thead><tbody>`);
    ex.sample.forEach((row, index) => {
      out.push(`<tr><td>${index + 1}</td><td>${hex(row.BeginAddress, 8)}</td><td>${hex(row.EndAddress, 8)}</td><td>${hex(row.UnwindInfoAddress, 8)}</td></tr>`);
    });
    out.push(`</tbody></table>`);
  }
  out.push(`</section>`);
}

export function renderBoundImports(pe: PeParseResult, out: string[]): void {
  if (!pe.boundImports) return;
  const bi = pe.boundImports;
  if (!bi.entries?.length) return;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Bound imports</h4>`);
  if (bi.warning) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${safe(bi.warning)}</div>`);
  }
  out.push(`<table class="table"><thead><tr><th>#</th><th>Module</th><th>TimeDateStamp</th><th>ForwarderRefs</th></tr></thead><tbody>`);
  bi.entries.forEach((e, index) => {
    out.push(`<tr><td>${index + 1}</td><td>${safe(e.name || "")}</td><td>${hex(e.TimeDateStamp, 8)}</td><td>${e.NumberOfModuleForwarderRefs}</td></tr>`);
  });
  out.push(`</tbody></table></section>`);
}

export function renderDelayImports(pe: PeParseResult, out: string[]): void {
  if (!pe.delayImports) return;
  const di = pe.delayImports;
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

export function renderCoverage(pe: PeParseResult, out: string[]): void {
  if (!pe.coverage) return;
  const cov = pe.coverage;
  if (!cov.length) return;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Coverage map (file offsets)</h4>`);
  out.push(`<div class="smallNote">Shows which parts of the file were recognized as headers, directories and section data. Gaps may indicate overlays or unknown data.</div>`);
  out.push(`<table class="table"><thead><tr><th>#</th><th>Label</th><th>Offset</th><th>Size</th></tr></thead><tbody>`);
  cov.forEach((seg, index) => {
    out.push(`<tr><td>${index + 1}</td><td>${safe(seg.label)}</td><td>${hex(seg.off, 8)}</td><td>${humanSize(seg.size)}</td></tr>`);
  });
  out.push(`</tbody></table></section>`);
}

export function renderSanity(pe: PeParseResult, out: string[]): void {
  const issues: string[] = [];
  if (pe.overlaySize > 0) {
    issues.push(`Overlay after last section: ${humanSize(pe.overlaySize)}.`);
  }
  if (pe.imageSizeMismatch) {
    issues.push("SizeOfImage does not match section layout.");
  }
  if (pe.debugWarning) {
    issues.push(pe.debugWarning);
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

