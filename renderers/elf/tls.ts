"use strict";

import { dd, safe } from "../../html-utils.js";
import type { ElfParseResult, ElfTlsInfo } from "../../analyzers/elf/types.js";
import { formatElfHex, formatElfList, formatElfMaybeHumanSize } from "./value-format.js";

const renderSegmentsTable = (tls: ElfTlsInfo): string => {
  if (!tls.segments.length) return `<div class="smallNote dim">No PT_TLS program headers present.</div>`;
  const rows = tls.segments
    .map(seg => {
      return (
        `<tr><td>${seg.index}</td><td>${safe(formatElfHex(seg.offset))}</td><td>${safe(formatElfHex(seg.vaddr))}</td>` +
        `<td>${formatElfMaybeHumanSize(seg.filesz)}</td><td>${formatElfMaybeHumanSize(seg.memsz)}</td><td>${safe(
          formatElfHex(seg.align)
        )}</td></tr>`
      );
    })
    .join("");
  return (
    `<details style="margin-top:.35rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show PT_TLS segments (${tls.segments.length})</summary>` +
      `<div class="tableWrap"><table class="table" style="margin-top:.35rem"><thead><tr>` +
      `<th>#</th><th>Offset</th><th>VirtAddr</th><th>FileSz</th><th>MemSz</th><th>Align</th>` +
      `</tr></thead><tbody>${rows}</tbody></table></div></details>`
  );
};

const renderSectionsTable = (tls: ElfTlsInfo): string => {
  if (!tls.sections.length) return `<div class="smallNote dim">No TLS-flagged sections found.</div>`;
  const rows = tls.sections
    .map(sec => {
      const name = sec.name ? `<b>${safe(sec.name)}</b>` : `<span class="dim">(unnamed)</span>`;
      return (
        `<tr><td>${sec.index}</td><td>${name}</td><td>${safe(formatElfHex(sec.offset))}</td><td>${formatElfMaybeHumanSize(
          sec.size
        )}</td><td>${safe(formatElfHex(sec.addr))}</td><td>${formatElfList(sec.flags)}</td></tr>`
      );
    })
    .join("");
  return (
    `<details style="margin-top:.35rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show TLS sections (${tls.sections.length})</summary>` +
      `<div class="tableWrap"><table class="table" style="margin-top:.35rem"><thead><tr>` +
      `<th>#</th><th>Name</th><th>Offset</th><th>Size</th><th>Addr</th><th>Flags</th>` +
      `</tr></thead><tbody>${rows}</tbody></table></div></details>`
  );
};

export function renderElfTls(elf: ElfParseResult, out: string[]): void {
  const tls = elf.tls;
  if (!tls) return;

  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">TLS</h4>`);
  out.push(
    `<div class="smallNote">Thread-local storage describes per-thread variables and the template copied into each new thread.</div>`
  );
  out.push(`<dl>`);
  out.push(dd("PT_TLS segments", safe(String(tls.segments.length))));
  out.push(dd("TLS sections", safe(String(tls.sections.length))));
  out.push(`</dl>`);
  out.push(renderSegmentsTable(tls));
  out.push(renderSectionsTable(tls));
  out.push(`</section>`);
}

