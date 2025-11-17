"use strict";

import { dd, safe } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";

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

const formatOffset = value => {
  if (value == null) return "-";
  if (typeof value === "bigint") return `0x${value.toString(16)}`;
  return toHex32(value, 8);
};

const renderSummary = (zip, out) => {
  const entries = zip.centralDirectory?.entries?.length || 0;
  const truncated = zip.centralDirectory?.truncated;
  const comment = zip.eocd.comment || "(none)";
  const cdOffset = formatOffset(zip.centralDirectory?.offset);
  const cdSize = formatSize(zip.centralDirectory?.size);
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">ZIP overview</h4>`);
  out.push(`<dl>`);
  out.push(dd("Central directory offset", cdOffset));
  out.push(dd("Central directory size", cdSize));
  out.push(dd("Entry count (parsed)", entries.toString()));
  out.push(dd("File comment", safe(comment)));
  if (truncated) {
    out.push(
      `<div class="smallNote">Central directory extends beyond the file size.</div>`
    );
  }
  out.push(`</dl>`);
  out.push(`</section>`);
};

const renderEocd = (zip, out) => {
  const { eocd } = zip;
  if (!eocd) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">End of central directory</h4>`);
  out.push(`<dl>`);
  out.push(dd("Offset", formatOffset(eocd.offset)));
  out.push(dd("Disk number", eocd.diskNumber.toString()));
  out.push(dd("Central dir disk", eocd.centralDirDisk.toString()));
  out.push(dd("Entries on this disk", eocd.entriesThisDisk.toString()));
  out.push(dd("Total entries", eocd.totalEntries.toString()));
  out.push(dd("Central dir size (EOCD)", formatSize(eocd.centralDirSize)));
  out.push(dd("Central dir offset (EOCD)", formatOffset(eocd.centralDirOffset)));
  out.push(dd("Comment length", eocd.commentLength.toString()));
  out.push(`</dl>`);
  out.push(`</section>`);
};

const renderZip64 = (zip, out) => {
  if (!zip.zip64 && !zip.zip64Locator) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">ZIP64 metadata</h4>`);
  out.push(`<dl>`);
  if (zip.zip64Locator) {
    out.push(dd("Locator offset", formatOffset(zip.zip64Locator.offset)));
    out.push(dd("ZIP64 EOCD offset", formatOffset(zip.zip64Locator.zip64EocdOffset)));
    out.push(dd("Total disks", zip.zip64Locator.totalDisks.toString()));
  }
  if (zip.zip64) {
    out.push(dd("EOCD offset", formatOffset(zip.zip64.offset)));
    out.push(dd("Record size", formatSize(zip.zip64.size)));
    out.push(dd("Version needed", zip.zip64.versionNeeded.toString()));
    out.push(dd("Entries (ZIP64)", zip.zip64.totalEntries.toString()));
    out.push(dd("Central dir size (ZIP64)", formatSize(zip.zip64.centralDirSize)));
    out.push(dd("Central dir offset (ZIP64)", formatOffset(zip.zip64.centralDirOffset)));
  }
  out.push(`</dl>`);
  out.push(`</section>`);
};

const describeFlags = entry => {
  const flags = [];
  if (entry.isUtf8) flags.push("UTF-8 names");
  if (entry.isEncrypted) flags.push("Encrypted");
  if (entry.usesDataDescriptor) flags.push("Data descriptor");
  return flags.length ? flags.join(", ") : "-";
};

const renderEntries = (zip, out) => {
  const cd = zip.centralDirectory;
  if (!cd?.entries?.length) return;
  const limit = 200;
  const entries = cd.entries.slice(0, limit);
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Central directory entries</h4>`);
  out.push(
    `<table class="table"><thead><tr>` +
      `<th>#</th><th>Name</th><th>Method</th><th>Comp size</th>` +
      `<th>Uncomp size</th><th>Modified</th><th>Flags</th>` +
    `</tr></thead><tbody>`
  );
  entries.forEach(entry => {
    const compSize = formatSize(entry.compressedSize);
    const uncompSize = formatSize(entry.uncompressedSize);
    const mod = safe(entry.modTimeIso || "-");
    out.push(
      `<tr><td>${entry.index}</td><td>${safe(entry.fileName)}</td>` +
        `<td>${safe(entry.compressionName)}</td>` +
        `<td>${compSize}</td><td>${uncompSize}</td>` +
        `<td>${mod}</td><td>${safe(describeFlags(entry))}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
  if (cd.entries.length > limit) {
    const remaining = cd.entries.length - limit;
    out.push(`<div class="smallNote">${remaining} more entries not shown.</div>`);
  }
  out.push(`</section>`);
};

const renderIssues = (zip, out) => {
  const issues = zip.issues || [];
  if (!issues.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4>`);
  out.push(`<ul>`);
  issues.forEach(issue => out.push(`<li>${safe(issue)}</li>`));
  out.push(`</ul>`);
  out.push(`</section>`);
};

export function renderZip(zip) {
  if (!zip) return "";
  const out = [];
  renderSummary(zip, out);
  renderEocd(zip, out);
  renderZip64(zip, out);
  renderEntries(zip, out);
  renderIssues(zip, out);
  return out.join("");
}
