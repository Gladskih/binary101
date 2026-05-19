"use strict";

import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import { formatHumanSize, formatUnixSecondsOrDash, toHex32 } from "../../binary-utils.js";
import type { GzipParseResult } from "../../analyzers/gzip/types.js";

const renderFlag = (label: string, active: boolean, tooltip?: string): string => {
  const cls = active ? "opt sel" : "opt dim";
  const title = tooltip ? ` title="${escapeHtml(tooltip)}"` : "";
  return `<span class="${cls}"${title}>${escapeHtml(label)}</span>`;
};

const renderIssues = (issues: string[] | null | undefined): string => {
  if (!issues || issues.length === 0) return "";
  return `<h4>Issues</h4><ul class="issueList">${issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`;
};

export function renderGzip(parsed: GzipParseResult | null | unknown): string {
  const data = parsed as GzipParseResult | null;
  if (!data) return "";

  const out: string[] = [];
  const header = data.header;
  const trailer = data.trailer;
  const stream = data.stream;

  out.push("<h3>gzip compressed data</h3>");

  out.push("<h4>Header</h4><dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(data.fileSize))));
  out.push(renderDefinitionRow("Compression method", escapeHtml(header.compressionMethodName || `${header.compressionMethod ?? "Unknown"}`)));
  out.push(
    renderDefinitionRow(
      "Flags",
      `<div class="optionsRow">` +
        renderFlag("FTEXT", header.flags.ftext, "ASCII text hint") +
        renderFlag("FHCRC", header.flags.fhcrc, "Header CRC16 is present") +
        renderFlag("FEXTRA", header.flags.fextra, "Extra field is present") +
        renderFlag("FNAME", header.flags.fname, "Original filename is present") +
        renderFlag("FCOMMENT", header.flags.fcomment, "Comment is present") +
      `</div>`
    )
  );
  if (header.flags.reservedBits) {
    out.push(renderDefinitionRow("Reserved flag bits", escapeHtml(toHex32(header.flags.reservedBits, 2))));
  }
  out.push(renderDefinitionRow("MTIME", escapeHtml(header.mtime != null ? formatUnixSecondsOrDash(header.mtime) : "-")));
  out.push(renderDefinitionRow("Extra flags (XFL)", escapeHtml(header.extraFlags != null ? toHex32(header.extraFlags, 2) : "-")));
  out.push(renderDefinitionRow("OS", escapeHtml(header.osName || (header.os != null ? `${header.os}` : "-"))));
  out.push(renderDefinitionRow("Header CRC16", escapeHtml(header.headerCrc16 != null ? toHex32(header.headerCrc16, 4) : "-")));
  out.push(renderDefinitionRow("Header bytes", escapeHtml(header.headerBytesTotal != null ? `${header.headerBytesTotal}` : "-")));

  if (header.extra) {
    const extraNote = header.extra.truncated
      ? `${header.extra.dataLength}/${header.extra.xlen} bytes (truncated)`
      : `${header.extra.xlen} bytes`;
    out.push(renderDefinitionRow("Extra field", escapeHtml(extraNote)));
  }
  out.push(renderDefinitionRow("Original filename", escapeHtml(header.fileName || "-")));
  out.push(renderDefinitionRow("Comment", escapeHtml(header.comment || "-")));

  if (header.truncated) {
    out.push(renderDefinitionRow("Header truncated", escapeHtml("Yes")));
  }

  out.push("</dl>");

  out.push("<h4>Trailer</h4><dl>");
  out.push(renderDefinitionRow("CRC32", escapeHtml(trailer.crc32 != null ? toHex32(trailer.crc32, 8) : "-")));
  out.push(
    renderDefinitionRow(
      "ISIZE (mod 2^32)",
      escapeHtml(trailer.isize != null ? formatHumanSize(trailer.isize) : "-")
    )
  );
  out.push(renderDefinitionRow("Trailer offset", escapeHtml(stream.trailerOffset != null ? `${stream.trailerOffset}` : "-")));
  if (trailer.truncated) {
    out.push(renderDefinitionRow("Trailer truncated", escapeHtml("Yes")));
  }
  out.push("</dl>");

  out.push("<h4>Stream layout</h4><dl>");
  out.push(renderDefinitionRow("Compressed data offset", escapeHtml(stream.compressedOffset != null ? `${stream.compressedOffset}` : "-")));
  out.push(renderDefinitionRow("Compressed data size", escapeHtml(stream.compressedSize != null ? formatHumanSize(stream.compressedSize) : "-")));
  out.push(renderDefinitionRow("File truncated", escapeHtml(stream.truncatedFile ? "Yes" : "No")));
  out.push("</dl>");

  out.push("<h4>Actions</h4>");
  out.push(
    `<button type="button" class="tableButton gzipDecompressButton" data-gzip-action="decompress">Decompress</button>`
  );

  out.push(renderIssues(data.issues));
  return out.join("");
}
