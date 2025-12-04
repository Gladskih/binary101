"use strict";

import { escapeHtml } from "../../html-utils.js";
import { toHex32 } from "../../binary-utils.js";
import type { RiffChunk } from "../../analyzers/riff/types.js";

const renderIndentedType = (chunk: RiffChunk): string => {
  const depth = Math.max(0, chunk.depth || 0);
  const padding = depth > 0 ? "&nbsp;".repeat(depth * 2) : "";
  const type = escapeHtml(chunk.id || "");
  return `${padding}${type}`;
};

const walkInOrder = (
  chunks: RiffChunk[],
  visit: (chunk: RiffChunk, index: number) => void
): void => {
  let counter = 0;
  const walk = (list: RiffChunk[]) => {
    for (const chunk of list) {
      visit(chunk, counter);
      counter += 1;
      if (chunk.children && chunk.children.length > 0) walk(chunk.children);
    }
  };
  walk(chunks);
};

export const renderChunkTable = (chunks: RiffChunk[] | null | undefined): string => {
  if (!chunks || chunks.length === 0) return "";
  const rows: string[] = [];
  walkInOrder(chunks, (chunk, index) => {
    const truncated = chunk.truncated ? ' class="dim"' : "";
    const paddedSize = chunk.paddedSize || chunk.size || 0;
    rows.push(
      `<tr${truncated}>` +
        `<td>${index}</td>` +
        `<td>${renderIndentedType(chunk)}</td>` +
        `<td>${escapeHtml(chunk.listType || "")}</td>` +
        `<td title="${toHex32(chunk.offset, 8)}">${chunk.offset}</td>` +
        `<td title="${toHex32(chunk.size, 8)}">${chunk.size} B</td>` +
        `<td title="${toHex32(paddedSize, 8)}">${paddedSize} B</td>` +
      "</tr>"
    );
  });
  return (
    '<h4>Chunks</h4><p>RIFF files are organized into four-character chunks. ' +
    "Offsets are measured from the start of the file. Sizes exclude the padding byte used " +
    "for even alignment.</p>" +
    '<table class="byteView"><thead><tr>' +
    "<th>#</th><th>Type</th><th>List type</th><th>Offset</th><th>Size</th><th>Padded</th>" +
    `</tr></thead><tbody>${rows.join("")}</tbody></table>`
  );
};
