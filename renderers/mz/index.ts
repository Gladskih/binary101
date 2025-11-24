// @ts-nocheck
"use strict";

import { dd, safe } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";

const hex16 = value => (value == null ? "-" : "0x" + toHex32(value, 4));
const hex32 = value => (value == null ? "-" : "0x" + toHex32(value, 8));
const describeNext = kind => {
  if (!kind) return "Plain MZ (no NE/PE header)";
  if (kind === "ne") return "NE (16-bit Windows/OS/2) header";
  if (kind === "le" || kind === "lx") return "Linear executable (LE/LX) header";
  if (kind === "pe") return "PE header";
  return kind.toUpperCase();
};
const segOff = (seg, off) => {
  if (seg == null || off == null) return "-";
  return `${toHex32(seg, 4)}:${toHex32(off, 4)}`;
};

const renderHeader = (mz, out) => {
  const h = mz.header || {};
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">MS-DOS header</h4>`);
  out.push(`<dl>`);
  out.push(dd("Signature", safe(h.e_magic || "-")));
  out.push(dd("Pages", `${h.e_cp || 0} (${formatHumanSize((h.e_cp || 0) * 512)})`));
  out.push(dd("Last page bytes", h.e_cblp?.toString() ?? "-"));
  out.push(dd("Relocation entries", h.e_crlc?.toString() ?? "0"));
  out.push(dd("Header size", `${h.e_cparhdr != null ? h.e_cparhdr * 16 : "-"} bytes`));
  out.push(dd("Min/Max extra", `${h.e_minalloc ?? "-"} / ${h.e_maxalloc ?? "-"}`));
  out.push(dd("Initial SP", segOff(h.e_ss, h.e_sp)));
  out.push(dd("Initial IP", segOff(h.e_cs, h.e_ip)));
  out.push(dd("Relocation table", hex16(h.e_lfarlc)));
  out.push(dd("Next header offset", hex32(h.e_lfanew)));
  out.push(dd("Next header type", safe(describeNext(mz.nextHeader))));
  out.push(`</dl>`);
  out.push(`</section>`);
};

const renderRelocations = (mz, out) => {
  const relocs = mz.relocations || [];
  if (!relocs.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Relocation table</h4>`);
  out.push(`<table class="table"><thead><tr><th>#</th><th>Segment</th><th>Offset</th></tr></thead><tbody>`);
  relocs.slice(0, 64).forEach(reloc => {
    out.push(
      `<tr><td>${reloc.index}</td><td>${hex16(reloc.segment)}</td><td>${hex16(reloc.offset)}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
  if (relocs.length > 64) {
    out.push(`<div class="smallNote">${relocs.length - 64} more entries not shown.</div>`);
  }
  out.push(`</section>`);
};

const renderStub = (mz, out) => {
  const stubStrings = mz.stubStrings || [];
  if (!stubStrings.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Stub text</h4>`);
  out.push(`<ul>`);
  stubStrings.forEach(text => out.push(`<li>${safe(text)}</li>`));
  out.push(`</ul>`);
  out.push(`</section>`);
};

const renderWarnings = (mz, out) => {
  const issues = mz.warnings || [];
  if (!issues.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4>`);
  out.push(`<ul>`);
  issues.forEach(issue => out.push(`<li>${safe(issue)}</li>`));
  out.push(`</ul>`);
  out.push(`</section>`);
};

export function renderMz(mz) {
  if (!mz) return "";
  const out = [];
  renderHeader(mz, out);
  renderRelocations(mz, out);
  renderStub(mz, out);
  renderWarnings(mz, out);
  return out.join("");
}
