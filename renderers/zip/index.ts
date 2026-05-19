"use strict";

import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import type {
  ZipCentralDirectoryEntry,
  ZipParseResult
} from "../../analyzers/zip/index.js";

const formatSize = (value: number | bigint | null | undefined): string => {
  if (value == null) return "-";
  if (typeof value === "bigint") {
    if (value <= BigInt(Number.MAX_SAFE_INTEGER)) {
      return formatHumanSize(Number(value));
    }
    return `${value.toString()} bytes`;
  }
  return formatHumanSize(value);
};

const formatOffset = (value: number | bigint | null | undefined): string => {
  if (value == null) return "-";
  if (typeof value === "bigint") return `0x${value.toString(16)}`;
  return toHex32(value, 8);
};

const renderSummary = (zip: ZipParseResult, out: string[]): void => {
  const entries = zip.centralDirectory?.entries?.length || 0;
  const truncated = zip.centralDirectory?.truncated;
  const comment = zip.eocd.comment || "(none)";
  const cdOffset = formatOffset(zip.centralDirectory?.offset);
  const cdSize = formatSize(zip.centralDirectory?.size);
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">ZIP overview</h4>`);
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Central directory offset", cdOffset));
  out.push(renderDefinitionRow("Central directory size", cdSize));
  out.push(renderDefinitionRow("Entry count (parsed)", entries.toString()));
  out.push(renderDefinitionRow("File comment", escapeHtml(comment)));
  if (truncated) {
    out.push(
      `<div class="smallNote">Central directory extends beyond the file size.</div>`
    );
  }
  out.push(`</dl>`);
  out.push(`</section>`);
};

const renderEocd = (zip: ZipParseResult, out: string[]): void => {
  const { eocd } = zip;
  if (!eocd) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">End of central directory</h4>`);
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Offset", formatOffset(eocd.offset)));
  out.push(renderDefinitionRow("Disk number", eocd.diskNumber.toString()));
  out.push(renderDefinitionRow("Central dir disk", eocd.centralDirDisk.toString()));
  out.push(renderDefinitionRow("Entries on this disk", eocd.entriesThisDisk.toString()));
  out.push(renderDefinitionRow("Total entries", eocd.totalEntries.toString()));
  out.push(renderDefinitionRow("Central dir size (EOCD)", formatSize(eocd.centralDirSize)));
  out.push(renderDefinitionRow("Central dir offset (EOCD)", formatOffset(eocd.centralDirOffset)));
  out.push(renderDefinitionRow("Comment length", eocd.commentLength.toString()));
  out.push(`</dl>`);
  out.push(`</section>`);
};

const renderZip64 = (zip: ZipParseResult, out: string[]): void => {
  if (!zip.zip64 && !zip.zip64Locator) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">ZIP64 metadata</h4>`);
  out.push(`<dl>`);
  if (zip.zip64Locator) {
    out.push(renderDefinitionRow("Locator offset", formatOffset(zip.zip64Locator.offset)));
    out.push(renderDefinitionRow("ZIP64 EOCD offset", formatOffset(zip.zip64Locator.zip64EocdOffset)));
    out.push(renderDefinitionRow("Total disks", zip.zip64Locator.totalDisks.toString()));
  }
  if (zip.zip64) {
    out.push(renderDefinitionRow("EOCD offset", formatOffset(zip.zip64.offset)));
    out.push(renderDefinitionRow("Record size", formatSize(zip.zip64.size)));
    out.push(renderDefinitionRow("Version needed", zip.zip64.versionNeeded.toString()));
    out.push(renderDefinitionRow("Entries (ZIP64)", zip.zip64.totalEntries.toString()));
    out.push(renderDefinitionRow("Central dir size (ZIP64)", formatSize(zip.zip64.centralDirSize)));
    out.push(renderDefinitionRow("Central dir offset (ZIP64)", formatOffset(zip.zip64.centralDirOffset)));
  }
  out.push(`</dl>`);
  out.push(`</section>`);
};

const describeFlags = (entry: ZipCentralDirectoryEntry): string => {
  const flags: string[] = [];
  if (entry.isUtf8) flags.push("UTF-8 names");
  if (entry.isEncrypted) flags.push("Encrypted");
  if (entry.usesDataDescriptor) flags.push("Data descriptor");
  return flags.length ? flags.join(", ") : "-";
};

const renderEntries = (zip: ZipParseResult, out: string[]): void => {
  const cd = zip.centralDirectory;
  if (!cd?.entries?.length) return;
  const limit = 200;
  const entries = cd.entries.slice(0, limit);
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Central directory entries</h4>`);
  out.push(
    `<table class="table"><thead><tr>` +
      `<th>#</th><th>Name</th><th>Method</th><th>Comp size</th>` +
      `<th>Uncomp size</th><th>Modified</th><th>Flags</th><th>Extract</th>` +
    `</tr></thead><tbody>`
  );
  const renderAction = (entry: ZipCentralDirectoryEntry): string => {
    if (entry.extractError) {
      return `<span class="smallNote">${escapeHtml(entry.extractError)}</span>`;
    }
    if (entry.dataOffset == null || entry.dataLength == null) {
      return `<span class="smallNote">Unavailable</span>`;
    }
    const label = entry.compressionMethod === 8 ? "Decompress" : "Download";
    return `<button type="button" class="tableButton zipExtractButton" data-zip-entry="${entry.index}">${label}</button>`;
  };
  entries.forEach((entry: ZipCentralDirectoryEntry) => {
    const compSize = formatSize(entry.compressedSize);
    const uncompSize = formatSize(entry.uncompressedSize);
    const mod = escapeHtml(entry.modTimeIso || "-");
    out.push(
      `<tr><td>${entry.index}</td><td>${escapeHtml(entry.fileName)}</td>` +
        `<td>${escapeHtml(entry.compressionName)}</td>` +
        `<td>${compSize}</td><td>${uncompSize}</td>` +
        `<td>${mod}</td><td>${escapeHtml(describeFlags(entry))}</td>` +
        `<td>${renderAction(entry)}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
  if (cd.entries.length > limit) {
    const remaining = cd.entries.length - limit;
    out.push(`<div class="smallNote">${remaining} more entries not shown.</div>`);
  }
  out.push(`</section>`);
};

const renderIssues = (zip: ZipParseResult, out: string[]): void => {
  const issues = zip.issues || [];
  if (!issues.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4>`);
  out.push(`<ul>`);
  issues.forEach(issue => out.push(`<li>${escapeHtml(issue)}</li>`));
  out.push(`</ul>`);
  out.push(`</section>`);
};

export function renderZip(zip: ZipParseResult | null): string {
  if (!zip) return "";
  const out: string[] = [];
  renderSummary(zip, out);
  renderEocd(zip, out);
  renderZip64(zip, out);
  renderEntries(zip, out);
  renderIssues(zip, out);
  return out.join("");
}
