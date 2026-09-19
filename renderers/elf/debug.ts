"use strict";

import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";
import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import type { ElfCommentInfo, ElfDebugLinkInfo, ElfParseResult } from "../../analyzers/elf/types.js";
import { formatElfHex } from "./value-format.js";
import { renderDwarfAnalysis } from "../dwarf.js";

const renderComment = (comment: ElfCommentInfo): string => {
  if (!comment.strings?.length) return "";
  const items = comment.strings.map(text => `<li class="mono">${escapeHtml(text)}</li>`).join("");
  return `<details style="margin-top:.35rem"><summary style="cursor:pointer">Compiler comments (.comment) (${comment.strings.length})</summary><ul>${items}</ul></details>`;
};

const renderCommentIssues = (comment: ElfCommentInfo): string => {
  if (!comment.issues?.length) return "";
  const items = comment.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">.comment notes</summary><ul>${items}</ul></details>`;
};

const renderDebugLink = (debugLink: ElfDebugLinkInfo, littleEndian: boolean): string => {
  const crc = debugLink.crc32 != null ? escapeHtml(formatElfHex(debugLink.crc32 >>> 0, 8)) : "-";
  const fileName = debugLink.fileName ? `<span class="mono">${escapeHtml(debugLink.fileName)}</span>` : "-";
  const parts: string[] = [];
  parts.push(`<details style="margin-top:.35rem"><summary style="cursor:pointer">Debug link (.gnu_debuglink)</summary>`);
  parts.push(`<dl>`);
  parts.push(renderDefinitionRow("File name", fileName));
  parts.push(renderDefinitionRow("CRC32", crc));
  parts.push(renderDefinitionRow("Endian", littleEndian ? "little-endian" : "big-endian"));
  parts.push(`</dl>`);
  if (debugLink.issues?.length) {
    const items = debugLink.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
    parts.push(`<ul class="smallNote">${items}</ul>`);
  }
  parts.push(`</details>`);
  return parts.join("");
};

function renderGoBuildInfo(info: NonNullable<ElfParseResult["goBuildInfo"]>, out: string[]): void {
  out.push(`<p>Go toolchain: ${escapeHtml(info.version)}</p>`);
  out.push(`<div class="tableWrap"><table class="table"><thead><tr>` +
    `<th>Record</th><th>Module / setting</th><th>Version / details</th></tr></thead><tbody>`);
  out.push(info.moduleInfo.trim().split("\n").filter(Boolean).map(line => {
    const [kind, name, ...details] = line.split("\t");
    return `<tr><td>${escapeHtml(kind ?? "")}</td><td>${escapeHtml(name ?? "")}</td>` +
      `<td>${escapeHtml(details.join(" "))}</td></tr>`;
  }).join(""));
  out.push(`</tbody></table></div>`);
}

export function renderElfDebug(elf: ElfParseResult, out: string[]): void {
  const comment = elf.comment;
  const debugLink = elf.debugLink;
  const dwarf = elf.dwarf;
  if (![comment, debugLink, dwarf, elf.goBuildInfo].some(Boolean)) return;
  out.push(renderElfSectionStart(`Build / debug`));
  out.push(`<div class="smallNote">Non-code metadata useful for attribution and external debug info.</div>`);
  if (elf.goBuildInfo) renderGoBuildInfo(elf.goBuildInfo, out);
  if (comment) {
    out.push(renderComment(comment));
    out.push(renderCommentIssues(comment));
  }
  if (debugLink) {
    out.push(renderDebugLink(debugLink, elf.littleEndian));
  }
  if (dwarf) {
    out.push(`<details style="margin-top:.35rem"><summary style="cursor:pointer">`);
    out.push(
      `DWARF debug information (${dwarf.units.length} ` +
      `unit${dwarf.units.length === 1 ? "" : "s"})</summary>`
    );
    out.push(renderDwarfAnalysis(dwarf));
    out.push(`</details>`);
  }
  out.push(renderElfSectionEnd());
}
