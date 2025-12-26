"use strict";

import { dd, safe } from "../../html-utils.js";
import { formatHumanSize, formatUnixSecondsOrDash, toHex32 } from "../../binary-utils.js";
import type { GzipParseResult } from "../../analyzers/gzip/types.js";

const renderFlag = (label: string, active: boolean, tooltip?: string): string => {
  const cls = active ? "opt sel" : "opt dim";
  const title = tooltip ? ` title="${safe(tooltip)}"` : "";
  return `<span class="${cls}"${title}>${safe(label)}</span>`;
};

const renderIssues = (issues: string[] | null | undefined): string => {
  if (!issues || issues.length === 0) return "";
  return `<h4>Issues</h4><ul class="issueList">${issues.map(issue => `<li>${safe(issue)}</li>`).join("")}</ul>`;
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
  out.push(dd("File size", safe(formatHumanSize(data.fileSize))));
  out.push(dd("Compression method", safe(header.compressionMethodName || `${header.compressionMethod ?? "Unknown"}`)));
  out.push(
    dd(
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
    out.push(dd("Reserved flag bits", safe(toHex32(header.flags.reservedBits, 2))));
  }
  out.push(dd("MTIME", safe(header.mtime != null ? formatUnixSecondsOrDash(header.mtime) : "-")));
  out.push(dd("Extra flags (XFL)", safe(header.extraFlags != null ? toHex32(header.extraFlags, 2) : "-")));
  out.push(dd("OS", safe(header.osName || (header.os != null ? `${header.os}` : "-"))));
  out.push(dd("Header CRC16", safe(header.headerCrc16 != null ? toHex32(header.headerCrc16, 4) : "-")));
  out.push(dd("Header bytes", safe(header.headerBytesTotal != null ? `${header.headerBytesTotal}` : "-")));

  if (header.extra) {
    const extraNote = header.extra.truncated
      ? `${header.extra.dataLength}/${header.extra.xlen} bytes (truncated)`
      : `${header.extra.xlen} bytes`;
    out.push(dd("Extra field", safe(extraNote)));
  }
  out.push(dd("Original filename", safe(header.fileName || "-")));
  out.push(dd("Comment", safe(header.comment || "-")));

  if (header.truncated) {
    out.push(dd("Header truncated", safe("Yes")));
  }

  out.push("</dl>");

  out.push("<h4>Trailer</h4><dl>");
  out.push(dd("CRC32", safe(trailer.crc32 != null ? toHex32(trailer.crc32, 8) : "-")));
  out.push(
    dd(
      "ISIZE (mod 2^32)",
      safe(trailer.isize != null ? formatHumanSize(trailer.isize) : "-")
    )
  );
  out.push(dd("Trailer offset", safe(stream.trailerOffset != null ? `${stream.trailerOffset}` : "-")));
  if (trailer.truncated) {
    out.push(dd("Trailer truncated", safe("Yes")));
  }
  out.push("</dl>");

  out.push("<h4>Stream layout</h4><dl>");
  out.push(dd("Compressed data offset", safe(stream.compressedOffset != null ? `${stream.compressedOffset}` : "-")));
  out.push(dd("Compressed data size", safe(stream.compressedSize != null ? formatHumanSize(stream.compressedSize) : "-")));
  out.push(dd("File truncated", safe(stream.truncatedFile ? "Yes" : "No")));
  out.push("</dl>");

  out.push(renderIssues(data.issues));
  return out.join("");
}

