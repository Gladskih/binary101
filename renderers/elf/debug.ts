"use strict";

import { dd, safe } from "../../html-utils.js";
import type { ElfCommentInfo, ElfDebugLinkInfo, ElfParseResult } from "../../analyzers/elf/types.js";
import { formatElfHex } from "./value-format.js";

const renderComment = (comment: ElfCommentInfo): string => {
  if (!comment.strings?.length) return "";
  const items = comment.strings.map(text => `<li class="mono">${safe(text)}</li>`).join("");
  return `<details style="margin-top:.35rem"><summary style="cursor:pointer">Compiler comments (.comment) (${comment.strings.length})</summary><ul>${items}</ul></details>`;
};

const renderCommentIssues = (comment: ElfCommentInfo): string => {
  if (!comment.issues?.length) return "";
  const items = comment.issues.map(issue => `<li>${safe(issue)}</li>`).join("");
  return `<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">.comment notes</summary><ul>${items}</ul></details>`;
};

const renderDebugLink = (debugLink: ElfDebugLinkInfo, littleEndian: boolean): string => {
  const crc = debugLink.crc32 != null ? safe(formatElfHex(debugLink.crc32 >>> 0, 8)) : "-";
  const fileName = debugLink.fileName ? `<span class="mono">${safe(debugLink.fileName)}</span>` : "-";
  const parts: string[] = [];
  parts.push(`<details style="margin-top:.35rem"><summary style="cursor:pointer">Debug link (.gnu_debuglink)</summary>`);
  parts.push(`<dl>`);
  parts.push(dd("File name", fileName));
  parts.push(dd("CRC32", crc));
  parts.push(dd("Endian", littleEndian ? "little-endian" : "big-endian"));
  parts.push(`</dl>`);
  if (debugLink.issues?.length) {
    const items = debugLink.issues.map(issue => `<li>${safe(issue)}</li>`).join("");
    parts.push(`<ul class="smallNote">${items}</ul>`);
  }
  parts.push(`</details>`);
  return parts.join("");
};

export function renderElfDebug(elf: ElfParseResult, out: string[]): void {
  const comment = elf.comment;
  const debugLink = elf.debugLink;
  if (!comment && !debugLink) return;

  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Build / debug</h4>`);
  out.push(`<div class="smallNote">Non-code metadata useful for attribution and external debug info.</div>`);

  if (comment) {
    out.push(renderComment(comment));
    out.push(renderCommentIssues(comment));
  }

  if (debugLink) {
    out.push(renderDebugLink(debugLink, elf.littleEndian));
  }

  out.push(`</section>`);
}

