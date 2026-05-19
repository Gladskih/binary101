"use strict";

import { hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import { renderRichHeader } from "./rich-header.js";

type DosHeaderField = readonly [label: string, value: string, hint: string];

const renderDosHeaderRow = (label: string, value: string, hint: string): string =>
  `<tr><th scope="row">${escapeHtml(label)}</th><td>${escapeHtml(value)}</td>` +
  `<td class="smallNote" style="margin:0;font-family:inherit">${escapeHtml(hint)}</td></tr>`;

const renderDosHeaderFields = (pe: PeParseResult, out: string[]): void => {
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr>` +
    `<th>Field</th><th>Value</th><th>Meaning</th></tr></thead><tbody>`
  );
  ([
    ["e_magic", "MZ", "DOS header signature. PE files begin with a small DOS program (stub)."],
    ["e_cblp", `${pe.dos.e_cblp} bytes last page`, "Number of bytes on last page of file (legacy)."],
    ["e_cp", `${pe.dos.e_cp} pages`, "File size measured in 512-byte pages (legacy)."],
    ["e_crlc", String(pe.dos.e_crlc), "Relocations count for the DOS MZ program (should be 0 for PE)."],
    ["e_cparhdr", `${pe.dos.e_cparhdr} paragraphs (>=4)`, "Header size in 16-byte paragraphs (MZ)."],
    ["e_minalloc", String(pe.dos.e_minalloc), "Minimum extra paragraphs needed (DOS)."],
    ["e_maxalloc", String(pe.dos.e_maxalloc), "Maximum extra paragraphs needed (DOS)."],
    ["e_ss", hex(pe.dos.e_ss, 4), "Initial stack segment for DOS stub (legacy)."],
    ["e_sp", hex(pe.dos.e_sp, 4), "Initial stack pointer for DOS stub (legacy)."],
    ["e_csum", hex(pe.dos.e_csum, 4), "Checksum for DOS program (usually 0)."],
    ["e_ip", hex(pe.dos.e_ip, 4), "Initial instruction pointer for DOS stub."],
    ["e_cs", hex(pe.dos.e_cs, 4), "Initial code segment for DOS stub."],
    ["e_lfarlc", hex(pe.dos.e_lfarlc, 4), "Offset to relocation table within DOS header (usually 0x40)."],
    ["e_oemid", hex(pe.dos.e_oemid, 4), "OEM identifier."],
    ["e_oeminfo", hex(pe.dos.e_oeminfo, 4), "OEM-specific information."],
    [
      "e_lfanew",
      hex(pe.dos.e_lfanew, 8),
      `File offset to PE signature (${pe.dos.e_lfanew >= 0x80 ? "typically near end of headers" : ""}).`
    ]
  ] satisfies DosHeaderField[]).forEach(([label, value, hint]) => {
    out.push(renderDosHeaderRow(label, value, hint));
  });
  out.push(`</tbody></table>`);
};

const renderDosStub = (pe: PeParseResult, out: string[]): void => {
  const stub = pe.dos.stub;
  out.push(`<div class="smallNote">DOS stub: ${stub.kind}${stub.note ? ` - ${escapeHtml(stub.note)}` : ""}</div>`);
  if (stub.strings?.length) {
    out.push(`<div class="mono smallNote">${stub.strings.map(x => `<div>${escapeHtml(String(x))}</div>`).join("")}</div>`);
  }
  if (pe.dos.rich) {
    out.push(`<div style="margin-top:.75rem">`);
    renderRichHeader(pe.dos.rich, out);
    out.push(`</div>`);
  } else {
    out.push(
      `<div class="smallNote" style="margin-top:.5rem">Rich header: not present (no DanS/Rich signature found in DOS stub).</div>`
    );
  }
};

export const renderDosHeader = (pe: PeParseResult, out: string[]): void => {
  out.push(renderPeSectionStart("DOS header"));
  renderDosHeaderFields(pe, out);
  renderDosStub(pe, out);
  out.push(renderPeSectionEnd());
};
