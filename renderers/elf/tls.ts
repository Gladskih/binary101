"use strict";

import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";
import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import type { ElfParseResult, ElfTlsInfo } from "../../analyzers/elf/types.js";
import { formatElfHex, formatElfList, formatElfMaybeHumanSize } from "./value-format.js";

const renderTlsTable = (label: string, count: number, headers: string[], rows: string): string => {
  const caption = count === 1 ? `<caption>${label}</caption>` : "";
  const table = `<div class="tableWrap"><table class="table">${caption}<thead><tr>` +
    headers.map(header => `<th scope="col">${header}</th>`).join("") +
    `</tr></thead><tbody>${rows}</tbody></table></div>`;
  return count === 1 ? table : `<details><summary>Show ${label} (${count})</summary>${table}</details>`;
};

const renderSegmentsTable = (tls: ElfTlsInfo): string => {
  if (!tls.segments.length) return `<div class="smallNote dim">No PT_TLS program headers present.</div>`;
  const rows = tls.segments
    .map(seg => {
      return (
        `<tr><td>${seg.index}</td><td>${escapeHtml(formatElfHex(seg.offset))}</td><td>${escapeHtml(formatElfHex(seg.vaddr))}</td>` +
        `<td>${formatElfMaybeHumanSize(seg.filesz)}</td><td>${formatElfMaybeHumanSize(seg.memsz)}</td><td>${escapeHtml(
          formatElfHex(seg.align)
        )}</td><td class="peNumeric">${seg.memsz >= seg.filesz
          ? formatElfMaybeHumanSize(seg.memsz - seg.filesz) : "Unavailable"}</td></tr>`
      );
    })
    .join("");
  return renderTlsTable("PT_TLS segments", tls.segments.length,
    ["#", "Offset", "VirtAddr", "FileSz", "MemSz", "Align", "Zero-filled bytes"], rows);
};

const renderSectionsTable = (tls: ElfTlsInfo): string => {
  if (!tls.sections.length) return `<div class="smallNote dim">No TLS-flagged sections found.</div>`;
  const rows = tls.sections
    .map(sec => {
      const name = sec.name ? `<b>${escapeHtml(sec.name)}</b>` : `<span class="dim">(unnamed)</span>`;
      return (
        `<tr><td>${sec.index}</td><td>${name}</td><td>${escapeHtml(formatElfHex(sec.offset))}</td><td>${formatElfMaybeHumanSize(
          sec.size
        )}</td><td>${escapeHtml(formatElfHex(sec.addr))}</td><td>${formatElfList(sec.flags)}</td></tr>`
      );
    })
    .join("");
  return renderTlsTable("TLS sections", tls.sections.length,
    ["#", "Name", "Offset", "Size", "Addr", "Flags"], rows);
};

export function renderElfTls(elf: ElfParseResult, out: string[]): void {
  const tls = elf.tls;
  if (!tls) return;

  out.push(renderElfSectionStart(`TLS`));
  out.push(
    '<div class="smallNote">Each thread gets its own TLS block. FileSz is the initialization image ' +
    '(typically .tdata). MemSz is the template size including the zero-filled part (typically .tbss). ' +
    "A .tbss section can share a link-time address with an ordinary section.</div>"
  );
  out.push(`<dl>`);
  out.push(renderDefinitionRow("PT_TLS segments", escapeHtml(String(tls.segments.length))));
  out.push(renderDefinitionRow("TLS sections", escapeHtml(String(tls.sections.length))));
  out.push(`</dl>`);
  out.push(renderSegmentsTable(tls));
  out.push(renderSectionsTable(tls));
  if (tls.issues?.length) {
    out.push(`<ul>${tls.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`);
  }
  out.push(renderElfSectionEnd());
}

