"use strict";

import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type { TgaDeveloperDirectory, TgaDeveloperTag } from "../../analyzers/tga/types.js";

const renderTagTable = (tags: TgaDeveloperTag[]): string => {
  if (!tags.length) return "<p>No tags.</p>";
  const rows = tags
    .map(tag => {
      const truncated = tag.truncated ? "Yes" : "No";
      return (
        "<tr>" +
        `<td>${escapeHtml(String(tag.tagNumber))}</td>` +
        `<td>${escapeHtml(`${tag.dataOffset} (${toHex32(tag.dataOffset, 8)})`)}</td>` +
        `<td>${escapeHtml(formatHumanSize(tag.dataSize))}</td>` +
        `<td>${escapeHtml(truncated)}</td>` +
        "</tr>"
      );
    })
    .join("");
  return (
    '<table class="byteView"><thead><tr>' +
    "<th>Tag</th><th>Offset</th><th>Size</th><th>Truncated</th>" +
    `</tr></thead><tbody>${rows}</tbody></table>`
  );
};

export const renderTgaDeveloperDirectory = (dev: TgaDeveloperDirectory): string => {
  const out: string[] = [];
  out.push("<h4>Developer directory</h4>");
  out.push(
    `<p>Offset: ${escapeHtml(`${dev.offset} (${toHex32(dev.offset, 8)})`)}, tags: ${escapeHtml(
      String(dev.tagCount ?? "?")
    )}</p>`
  );
  out.push(renderTagTable(dev.tags));
  return out.join("");
};

