"use strict";

import { humanSize, hex, isoOrDash } from "../../binary-utils.js";
import { dd, safe } from "../../html-utils.js";
import { GUARD_FLAGS } from "../../analyzers/pe/constants.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import type { PeLoadConfig } from "../../analyzers/pe/debug-loadcfg.js";
import type { PeTlsDirectory } from "../../analyzers/pe/types.js";

const formatVa = (value: number | bigint, isPlus: boolean): string => {
  if (!value) return "-";
  return isPlus ? `0x${BigInt(value).toString(16)}` : hex(Number(value), 8);
};

const renderGuardFlags = (lc: PeLoadConfig, out: string[]): void => {
  if (typeof lc.GuardFlags !== "number") return;
  const flags = GUARD_FLAGS.filter(([bit]) => (lc.GuardFlags & bit) !== 0).map(([, name]) => name);
  out.push(
    dd(
      "GuardFlags",
      lc.GuardFlags ? hex(lc.GuardFlags, 8) : "0",
      flags.length ? flags.join(", ") : "No CFG-related flags set."
    )
  );
};

export function renderLoadConfig(pe: PeParseResult, out: string[]): void {
  if (!pe.loadcfg) return;
  const lc = pe.loadcfg;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Load Config</h4><dl>`);
  out.push(dd("Size", hex(lc.Size, 8), "Structure size of IMAGE_LOAD_CONFIG_DIRECTORY."));
  out.push(dd("TimeDateStamp", isoOrDash(lc.TimeDateStamp), "Build timestamp for load config data."));
  out.push(dd("Version", `${lc.Major}.${lc.Minor}`, "Load config version (varies between OS/toolchain versions)."));
  out.push(dd("SecurityCookie", formatVa(lc.SecurityCookie, pe.opt.isPlus), "Address of the GS cookie (stack guard)."));
  out.push(dd("SEHandlerTable", formatVa(lc.SEHandlerTable, pe.opt.isPlus), "SafeSEH handler table (x86 only)."));
  out.push(dd("SEHandlerCount", String(lc.SEHandlerCount ?? "-"), "Number of SafeSEH handlers (x86)."));
  out.push(dd("GuardCFFunctionTable", formatVa(lc.GuardCFFunctionTable, pe.opt.isPlus), "CFG function table VA."));
  out.push(dd("GuardCFFunctionCount", String(lc.GuardCFFunctionCount ?? "-"), "Number of CFG functions listed."));
  renderGuardFlags(lc, out);
  out.push(`</dl></section>`);
}

export function renderDebug(pe: PeParseResult, out: string[]): void {
  if (!pe.rsds && !pe.debugWarning) return;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Debug (PDB)</h4>`);
  if (pe.rsds) {
    out.push(`<dl>`);
    out.push(dd("CodeView", "RSDS", "CodeView debug directory entry with RSDS signature."));
    out.push(dd("GUID", (pe.rsds.guid || "").toUpperCase(), "PDB signature GUID used to match correct PDB file."));
    out.push(dd("Age", String(pe.rsds.age), "PDB age; increments on certain rebuilds."));
    out.push(dd("Path", pe.rsds.path, "Path to PDB as recorded at link time (can be absolute)."));
    out.push(`</dl>`);
  }
  if (pe.debugWarning) {
    out.push(`<div class="smallNote">${safe(pe.debugWarning)}</div>`);
  }
  out.push(`</section>`);
}

export function renderImports(pe: PeParseResult, out: string[]): void {
  if (!pe.imports?.length && !pe.importsWarning) return;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Import table</h4><div class="smallNote">Imports list functions this file expects other modules to provide. Hint index speeds up runtime name lookup, and ordinal-only imports often point to more special or low-level routines.</div>`);
  if (pe.importsWarning) {
    out.push(`<div class="smallNote" style="color:var(--warn-fg)">${safe(pe.importsWarning)}</div>`);
  }
  for (const mod of pe.imports) {
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
  out.push(`</section>`);
}

export function renderExports(pe: PeParseResult, out: string[]): void {
  if (!pe.exports) return;
  const ex = pe.exports;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Export directory</h4><dl>`);
  out.push(dd("Name", safe(ex.dllName || ""), "Exported DLL name recorded by the linker."));
  out.push(dd("OrdinalBase", String(ex.Base), "Base value added to function indices to form ordinals."));
  out.push(dd("Functions", String(ex.NumberOfFunctions), "Total entries in Export Address Table (including unnamed)."));
  out.push(dd("Names", String(ex.NumberOfNames), "Number of entries with names (Export Name Ptr & Ord tables)."));
  out.push(`</dl>`);
  if (ex.entries?.length) {
    out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show entries (${ex.entries.length})</summary>`);
    out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Ordinal</th><th>Name</th><th>RVA</th><th>Forwarder</th></tr></thead><tbody>`);
    ex.entries.slice(0, 2000).forEach((e, index) => {
      out.push(`<tr><td>${index + 1}</td><td>${e.ordinal}</td><td>${e.name ? safe(e.name) : "-"}</td><td>${hex(e.rva, 8)}</td><td>${e.forwarder ? safe(e.forwarder) : "-"}</td></tr>`);
    });
    out.push(`</tbody></table></details>`);
  }
  out.push(`</section>`);
}

export function renderTls(pe: PeParseResult, out: string[]): void {
  if (!pe.tls) return;
  const t: PeTlsDirectory = pe.tls;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">TLS directory</h4><dl>`);
  out.push(dd("StartAddressOfRawData", "0x" + BigInt(t.StartAddressOfRawData).toString(16), "VA for beginning of TLS template data."));
  out.push(dd("EndAddressOfRawData", "0x" + BigInt(t.EndAddressOfRawData).toString(16), "VA for end of TLS template data."));
  out.push(dd("AddressOfIndex", "0x" + BigInt(t.AddressOfIndex).toString(16), "VA of TLS index used by the loader."));
  out.push(dd("AddressOfCallBacks", "0x" + BigInt(t.AddressOfCallBacks).toString(16), "VA of null-terminated array of TLS callbacks (if present)."));
  out.push(dd("CallbackCount", String(t.CallbackCount ?? 0), "Number of TLS callbacks determined by scanning callback pointer array until NULL."));
  out.push(dd("SizeOfZeroFill", String(t.SizeOfZeroFill ?? 0), "Bytes of zero-fill padding (TLS)."));
  out.push(dd("Characteristics", hex(t.Characteristics || 0, 8), "Reserved (should be 0)."));
  out.push(`</dl></section>`);
}

export function renderClr(pe: PeParseResult, out: string[]): void {
  if (!pe.clr) return;
  const c = pe.clr;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">CLR (.NET) header</h4><dl>`);
  out.push(dd("Size", String(c.cb), "Size of IMAGE_COR20_HEADER in bytes."));
  out.push(dd("RuntimeVersion", `${c.MajorRuntimeVersion}.${c.MinorRuntimeVersion}`, "CLR runtime version required by this assembly."));
  out.push(dd("MetaData", `RVA ${hex(c.MetaDataRVA, 8)} Size ${humanSize(c.MetaDataSize)}`, "Location and size of CLR metadata streams (tables/heap)."));
  out.push(dd("Flags", hex(c.Flags, 8), "CLR image flags."));
  out.push(dd("EntryPointToken", hex(c.EntryPointToken, 8), "Managed entry point (token) for mixed-mode assemblies."));
  out.push(`</dl>`);
  if (c.meta) {
    if (c.meta.version) {
      out.push(`<div class="smallNote">Metadata version: ${safe(c.meta.version)}</div>`);
    }
    if (c.meta.streams?.length) {
      out.push(`<details style="margin-top:.35rem"><summary>Metadata streams (${c.meta.streams.length})</summary>`);
      out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Name</th><th>Offset</th><th>Size</th></tr></thead><tbody>`);
      c.meta.streams.forEach((stream, index) => {
        out.push(`<tr><td>${index + 1}</td><td>${safe(stream.name)}</td><td>${hex(stream.offset, 8)}</td><td>${humanSize(stream.size)}</td></tr>`);
      });
      out.push(`</tbody></table></details>`);
    }
  }
  out.push(`</section>`);
}

export function renderSecurity(pe: PeParseResult, out: string[]): void {
  if (!pe.security) return;
  const s = pe.security;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Security (WIN_CERTIFICATE)</h4><dl>`);
  out.push(dd("Certificate records", String(s.count ?? 0), "Number of certificate blobs present (Authenticode)."));
  out.push(`</dl>`);
  if (s.certs?.length) {
    out.push(`<table class="table"><thead><tr><th>#</th><th>Length</th><th>Revision</th><th>Type</th></tr></thead><tbody>`);
    s.certs.forEach((cert, index) => {
      out.push(`<tr><td>${index + 1}</td><td>${humanSize(cert.Length)}</td><td>${hex(cert.Revision, 4)}</td><td>${hex(cert.CertificateType, 4)}</td></tr>`);
    });
    out.push(`</tbody></table>`);
  }
  out.push(`</section>`);
}

export function renderIat(pe: PeParseResult, out: string[]): void {
  if (!pe.iat) return;
  const t = pe.iat;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Import Address Table (IAT)</h4><dl>`);
  out.push(dd("RVA", hex(t.rva, 8), "RVA of the runtime IAT used by the loader to place resolved addresses."));
  out.push(dd("Size", humanSize(t.size), "Total size of the IAT in bytes."));
  out.push(`</dl></section>`);
}

