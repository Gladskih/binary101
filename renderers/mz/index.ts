"use strict";

import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import type { MzParseResult, MzRelocationEntry } from "../../analyzers/mz/index.js";

const hex16 = (value: number | null | undefined): string =>
  value == null ? "-" : "0x" + toHex32(value, 4);
const hex32 = (value: number | null | undefined): string =>
  value == null ? "-" : "0x" + toHex32(value, 8);
const describeNext = (kind: string | undefined): string => {
  if (!kind) return "Plain MZ (no NE/PE header)";
  if (kind === "ne") return "NE (16-bit Windows/OS/2) header";
  if (kind === "le" || kind === "lx") return "Linear executable (LE/LX) header";
  if (kind === "pe") return "PE header";
  return kind.toUpperCase();
};
const segOff = (seg: number | null | undefined, off: number | null | undefined): string => {
  if (seg == null || off == null) return "-";
  return `${toHex32(seg, 4)}:${toHex32(off, 4)}`;
};

const renderHeader = (mz: MzParseResult, out: string[]): void => {
  const h = mz.header;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">MS-DOS header</h4>`);
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Signature", escapeHtml(h.e_magic || "-")));
  out.push(renderDefinitionRow("Pages", `${h.e_cp || 0} (${formatHumanSize((h.e_cp || 0) * 512)})`));
  out.push(renderDefinitionRow("Last page bytes", h.e_cblp?.toString() ?? "-"));
  out.push(renderDefinitionRow("Relocation entries", h.e_crlc?.toString() ?? "0"));
  out.push(renderDefinitionRow("Header size", `${h.e_cparhdr != null ? h.e_cparhdr * 16 : "-"} bytes`));
  out.push(renderDefinitionRow("Min/Max extra", `${h.e_minalloc ?? "-"} / ${h.e_maxalloc ?? "-"}`));
  out.push(renderDefinitionRow("Initial SP", segOff(h.e_ss, h.e_sp)));
  out.push(renderDefinitionRow("Initial IP", segOff(h.e_cs, h.e_ip)));
  out.push(renderDefinitionRow("Relocation table", hex16(h.e_lfarlc)));
  out.push(renderDefinitionRow("Next header offset", hex32(h.e_lfanew)));
  out.push(renderDefinitionRow("Next header type", escapeHtml(describeNext(mz.nextHeader))));
  out.push(`</dl>`);
  out.push(`</section>`);
};

const renderRelocations = (mz: MzParseResult, out: string[]): void => {
  const relocs = mz.relocations || [];
  if (!relocs.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Relocation table</h4>`);
  out.push(`<table class="table"><thead><tr><th>#</th><th>Segment</th><th>Offset</th></tr></thead><tbody>`);
  relocs.slice(0, 64).forEach((reloc: MzRelocationEntry) => {
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

const renderStub = (mz: MzParseResult, out: string[]): void => {
  const stubStrings = mz.stubStrings || [];
  if (!stubStrings.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Stub text</h4>`);
  out.push(`<ul>`);
  stubStrings.forEach(text => out.push(`<li>${escapeHtml(text)}</li>`));
  out.push(`</ul>`);
  out.push(`</section>`);
};

const renderWarnings = (mz: MzParseResult, out: string[]): void => {
  const issues = mz.warnings || [];
  if (!issues.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4>`);
  out.push(`<ul>`);
  issues.forEach(issue => out.push(`<li>${escapeHtml(issue)}</li>`));
  out.push(`</ul>`);
  out.push(`</section>`);
};

export function renderMz(mz: MzParseResult | null): string {
  if (!mz) return "";
  const out: string[] = [];
  renderHeader(mz, out);
  renderRelocations(mz, out);
  renderStub(mz, out);
  renderWarnings(mz, out);
  return out.join("");
}
