"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { dd, safe } from "../../html-utils.js";
import type {
  PeWindowsParseResult
} from "../../analyzers/pe/index.js";
import type { PeImportParseResult } from "../../analyzers/pe/imports.js";
import { peSectionNameValue } from "../../analyzers/pe/section-name.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

type PeImportsSection = PeImportParseResult;
type PeExportSection = NonNullable<PeWindowsParseResult["exports"]>;
type PeTlsSection = NonNullable<PeWindowsParseResult["tls"]>;
type PeIatSection = NonNullable<PeWindowsParseResult["iat"]>;
// Microsoft PE format, "Section Flags":
// IMAGE_SCN_GPREL marks sections whose data is referenced through the global pointer (GP).
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
const IMAGE_SCN_GPREL = 0x00008000;

export function renderImports(imports: PeImportsSection, out: string[]): void {
  if (!imports.entries.length && !imports.warning) return;
  out.push(renderPeSectionStart("Import table"));
  out.push(`<div class="smallNote">Imports list functions this file expects other modules to provide. Hint index speeds up runtime name lookup, and ordinal-only imports often point to more special or low-level routines.</div>`);
  if (imports.warning) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${safe(imports.warning)}</div>`);
  }
  for (const mod of imports.entries) {
    const dll = safe(mod.dll || "(unknown DLL)");
    out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>${dll}</b> \u2014 ${mod.functions?.length || 0} function(s)</summary>`);
    if (mod.functions?.length) {
      out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Hint</th><th>Name / Ordinal</th></tr></thead><tbody>`);
      mod.functions.forEach((fn, index) => {
        const hint = fn.hint != null ? String(fn.hint) : "-";
        const nm = fn.name ? safe(fn.name) : fn.ordinal != null ? "ORD " + fn.ordinal : "-";
        out.push(`<tr><td>${index + 1}</td><td>${hint}</td><td>${nm}</td></tr>`);
      });
      out.push(`</tbody></table>`);
    }
    out.push(`</details>`);
  }
  out.push(renderPeSectionEnd());
}

export function renderExports(ex: PeExportSection, out: string[]): void {
  out.push(
    renderPeSectionStart(
      "Export directory",
      `${ex.entries?.length ?? 0} entr${(ex.entries?.length ?? 0) === 1 ? "y" : "ies"}`
    )
  );
  out.push(`<dl>`);
  out.push(dd("Name", safe(ex.dllName || ""), "Exported DLL name recorded by the linker."));
  out.push(dd("OrdinalBase", String(ex.Base), "Base value added to function indices to form ordinals."));
  out.push(dd("Functions", String(ex.NumberOfFunctions), "Total entries in Export Address Table (including unnamed)."));
  out.push(dd("Names", String(ex.NumberOfNames), "Number of entries with names (Export Name Ptr & Ord tables)."));
  out.push(`</dl>`);
  if (ex.issues?.length) {
    out.push(`<ul class="smallNote">`);
    ex.issues.forEach(issue => out.push(`<li>${safe(issue)}</li>`));
    out.push(`</ul>`);
  }
  if (ex.entries?.length) {
    out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show entries (${ex.entries.length})</summary>`);
    out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Ordinal</th><th>Name</th><th>RVA</th><th>Forwarder</th></tr></thead><tbody>`);
    ex.entries.forEach((e, index) => {
      out.push(`<tr><td>${index + 1}</td><td>${e.ordinal}</td><td>${e.name ? safe(e.name) : "-"}</td><td>${hex(e.rva, 8)}</td><td>${e.forwarder ? safe(e.forwarder) : "-"}</td></tr>`);
    });
    out.push(`</tbody></table></details>`);
  }
  out.push(renderPeSectionEnd());
}

export function renderTls(t: PeTlsSection, out: string[]): void {
  out.push(
    renderPeSectionStart(
      "TLS directory",
      t.parsed === false
        ? "unparsed"
        : `${t.CallbackCount ?? 0} callback${(t.CallbackCount ?? 0) === 1 ? "" : "s"}`
    )
  );
  if (t.warnings?.length) {
    out.push(`<ul class="smallNote">`);
    t.warnings.forEach(warning => out.push(`<li>${safe(warning)}</li>`));
    out.push(`</ul>`);
  }
  if (t.parsed === false) {
    out.push(renderPeSectionEnd());
    return;
  }
  out.push(`<dl>`);
  out.push(dd("StartAddressOfRawData", "0x" + BigInt(t.StartAddressOfRawData).toString(16), "VA for beginning of TLS template data."));
  out.push(dd("EndAddressOfRawData", "0x" + BigInt(t.EndAddressOfRawData).toString(16), "VA for end of TLS template data."));
  out.push(dd("AddressOfIndex", "0x" + BigInt(t.AddressOfIndex).toString(16), "VA of TLS index used by the loader."));
  out.push(dd("AddressOfCallBacks", "0x" + BigInt(t.AddressOfCallBacks).toString(16), "VA of null-terminated array of TLS callbacks (if present)."));
  out.push(dd("CallbackCount", String(t.CallbackCount ?? 0), "Number of TLS callbacks determined by scanning callback pointer array until NULL."));
  out.push(dd("SizeOfZeroFill", String(t.SizeOfZeroFill ?? 0), "Bytes of zero-fill padding (TLS)."));
  out.push(dd("Characteristics", hex(t.Characteristics || 0, 8), "Reserved (should be 0)."));
  out.push(`</dl>`);
  out.push(renderPeSectionEnd());
}

export { renderClr } from "./clr.js";
export { renderSecurity } from "./security-view.js";

export function renderIat(t: PeIatSection, out: string[]): void {
  out.push(renderPeSectionStart("Import Address Table (IAT)"));
  if (t.warnings?.length) {
    out.push(`<ul class="smallNote">`);
    t.warnings.forEach(warning => out.push(`<li>${safe(warning)}</li>`));
    out.push(`</ul>`);
  }
  out.push(`<dl>`);
  out.push(dd("RVA", hex(t.rva, 8), "RVA of the runtime IAT used by the loader to place resolved addresses."));
  out.push(dd("Size", humanSize(t.size), "Total size of the IAT in bytes."));
  out.push(`</dl>`);
  out.push(renderPeSectionEnd());
}

export function renderArchitectureDirectory(pe: PeWindowsParseResult, out: string[]): void {
  if (!pe.architecture) return;
  out.push(renderPeSectionStart("Architecture directory", "reserved slot"));
  if (pe.architecture.warnings?.length) {
    out.push(`<ul class="smallNote">`);
    pe.architecture.warnings.forEach(warning => out.push(`<li>${safe(warning)}</li>`));
    out.push(`</ul>`);
  }
  out.push(`<dl>`);
  out.push(dd("RVA", hex(pe.architecture.rva, 8), "Reserved directory entry. The PE specification says this field must be zero."));
  out.push(dd("Size", humanSize(pe.architecture.size), "Reserved directory entry. The PE specification says this field must be zero."));
  out.push(`</dl>`);
  out.push(
    `<div class="smallNote">This slot is reserved in the PE data-directory table. Non-zero values are mainly useful as anomaly indicators or signs of a non-standard producer.</div>`
  );
  out.push(renderPeSectionEnd());
}

export function renderGlobalPtrDirectory(pe: PeWindowsParseResult, out: string[]): void {
  if (!pe.globalPtr) return;
  const gpRelSections = (pe.sections ?? []).filter(
    section => (section.characteristics & IMAGE_SCN_GPREL) !== 0
  );
  out.push(
    renderPeSectionStart(
      "Global pointer (GP)",
      `${gpRelSections.length} GP-relative section${gpRelSections.length === 1 ? "" : "s"}`
    )
  );
  if (pe.globalPtr.warnings?.length) {
    out.push(`<ul class="smallNote">`);
    pe.globalPtr.warnings.forEach(warning => out.push(`<li>${safe(warning)}</li>`));
    out.push(`</ul>`);
  }
  out.push(`<dl>`);
  out.push(dd("Value RVA", hex(pe.globalPtr.rva, 8), "RVA of the value to be stored in the global pointer register."));
  out.push(dd("Size", humanSize(pe.globalPtr.size), "The PE specification says the Size member of GLOBALPTR must be zero."));
  out.push(
    dd(
      "GP-relative sections",
      gpRelSections.length
        ? safe(gpRelSections.map(section => peSectionNameValue(section.name) || "(unnamed)").join(", "))
        : "-",
      "Sections flagged IMAGE_SCN_GPREL contain data referenced through the global pointer (GP)."
    )
  );
  out.push(`</dl>`);
  out.push(
    `<div class="smallNote">GLOBALPTR is machine-specific and the spec defines only the RVA field here; it does not define a separate variable-size table to decode.</div>`
  );
  out.push(renderPeSectionEnd());
}
