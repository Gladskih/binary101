"use strict";

import { dd, safe } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";

const formatOffset = value => {
  if (value == null) return "-";
  if (typeof value === "bigint") return `0x${value.toString(16)}`;
  return toHex32(value, 8);
};

const formatSize = value => {
  if (value == null) return "-";
  if (typeof value === "bigint") {
    if (value <= BigInt(Number.MAX_SAFE_INTEGER)) {
      return formatHumanSize(Number(value));
    }
    return `${value.toString()} bytes`;
  }
  return formatHumanSize(value);
};

const toSafeNumber = value => {
  if (typeof value === "number") return value;
  if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  return null;
};

const formatSizeDetailed = value => {
  if (value == null) return "-";
  const safeNumber = toSafeNumber(value);
  if (safeNumber != null) return formatHumanSize(safeNumber);
  const asBigInt = typeof value === "bigint" ? value : BigInt(Math.max(value, 0));
  return `${asBigInt.toString()} bytes`;
};

const describeCoders = coders => {
  if (!coders?.length) return "-";
  return coders
    .map(coder => {
      const suffix = coder.archHint ? ` (${coder.archHint})` : "";
      return `${coder.id}${suffix}`;
    })
    .join(" + ");
};

const describeArchiveFlags = flags => {
  if (!flags) return "-";
  const parts = [];
  parts.push(flags.isSolid ? "Solid archive" : "Non-solid archive");
  parts.push(flags.isHeaderEncrypted ? "Header encrypted" : "Header not encrypted");
  parts.push(flags.hasEncryptedContent ? "Contains encrypted data" : "No encrypted files");
  return parts.join(", ");
};

const formatRatio = value => {
  if (value == null || !Number.isFinite(value)) return "-";
  return `${value.toFixed(1)}%`;
};

const renderOverview = (sevenZip, out) => {
  const header = sevenZip.startHeader || {};
  const next = sevenZip.nextHeader || {};
  const flags = sevenZip.structure?.archiveFlags;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">7z overview</h4>`);
  out.push(`<dl>`);
  out.push(dd("Version", `${header.versionMajor}.${header.versionMinor}`));
  out.push(dd("Start header CRC", toHex32(header.startHeaderCrc, 8)));
  out.push(dd("Next header offset", formatOffset(header.absoluteNextHeaderOffset)));
  out.push(dd("Next header size", formatSize(header.nextHeaderSize)));
  out.push(dd("Next header CRC", toHex32(next.crc ?? header.nextHeaderCrc, 8)));
  out.push(dd("Header kind", safe(next.parsed?.kind || "unknown")));
  out.push(dd("Archive flags", safe(describeArchiveFlags(flags))));
  out.push(`</dl>`);
  out.push(`</section>`);
};

const describeFileType = file => {
  if (file.isAnti) return "Anti-item";
  if (file.isDirectory) return "Directory";
  if (file.isEmptyStream && file.isEmptyFile) return "Empty file";
  if (file.isEmptyStream) return "Metadata only";
  if (file.hasStream === false) return "No stream";
  return "File";
};

const renderFolders = (sevenZip, out) => {
  const folders = sevenZip.structure?.folders || [];
  if (!folders.length) return;
  out.push(`<section>`);
  out.push(
    `<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Compression folders (${folders.length})</h4>`
  );
  out.push(
    `<table class="table"><thead><tr>` +
      `<th>#</th><th>Coders</th><th>Unpacked size</th><th>Packed size</th><th>Encrypted?</th>` +
    `</tr></thead><tbody>`
  );
  folders.forEach((folder, index) => {
    const coders = safe(describeCoders(folder.coders));
    const unpacked = formatSizeDetailed(folder.unpackSize);
    const packed = formatSizeDetailed(folder.packedSize);
    const encrypted = folder.isEncrypted ? "Yes" : "No";
    out.push(
      `<tr><td>${index + 1}</td><td>${coders}</td>` +
        `<td>${unpacked}</td><td>${packed}</td><td>${encrypted}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
  out.push(`</section>`);
};

const renderFiles = (sevenZip, out) => {
  const files = sevenZip.structure?.files || [];
  const folders = sevenZip.structure?.folders || [];
  if (!files.length) return;
  const limit = 200;
  const shown = files.slice(0, limit);
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Files (${files.length})</h4>`);
  out.push(
    `<table class="table"><thead><tr>` +
      `<th>#</th><th>Name</th><th>Type</th><th>Uncompressed</th><th>Packed</th>` +
      `<th>Ratio</th><th>Method</th><th>CRC</th><th>Modified</th><th>Attributes</th><th>Flags</th>` +
    `</tr></thead><tbody>`
  );
  shown.forEach(file => {
    const type = describeFileType(file);
    const modified = file.modifiedTime ? safe(file.modifiedTime) : "-";
    const attrs = file.attributes ? safe(file.attributes) : "-";
    const folder =
      file.folderIndex != null && file.folderIndex >= 0 ? folders[file.folderIndex] : null;
    const method = folder ? safe(describeCoders(folder.coders)) : "-";
    const unpacked = formatSizeDetailed(file.uncompressedSize);
    const packed = formatSizeDetailed(file.packedSize);
    const ratio = formatRatio(file.compressionRatio);
    const crc = file.crc32 != null ? toHex32(file.crc32, 8) : "-";
    const flags = [];
    if (file.isDirectory) flags.push("dir");
    if (file.isEncrypted) flags.push("enc");
    if (file.isEmpty) flags.push("empty");
    if (file.hasStream === false) flags.push("no-stream");
    const flagText = flags.length ? flags.join(", ") : "-";
    out.push(
      `<tr><td>${file.index}</td><td>${safe(file.name)}</td>` +
        `<td>${safe(type)}</td><td>${unpacked}</td><td>${packed}</td>` +
        `<td>${ratio}</td><td>${method}</td><td>${crc}</td>` +
        `<td>${modified}</td><td>${attrs}</td><td>${flagText}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
  if (files.length > limit) {
    const remaining = files.length - limit;
    out.push(`<div class="smallNote">${remaining} more entries not shown.</div>`);
  }
  out.push(`</section>`);
};

const renderIssues = (sevenZip, out) => {
  const issues = sevenZip.issues || [];
  if (!issues.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4>`);
  out.push(`<ul>`);
  issues.forEach(issue => out.push(`<li>${safe(issue)}</li>`));
  out.push(`</ul>`);
  out.push(`</section>`);
};

export function renderSevenZip(sevenZip) {
  if (!sevenZip || !sevenZip.is7z) return "";
  const out = [];
  renderOverview(sevenZip, out);
  renderFolders(sevenZip, out);
  renderFiles(sevenZip, out);
  renderIssues(sevenZip, out);
  return out.join("");
}
