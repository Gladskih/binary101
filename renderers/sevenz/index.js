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

const renderOverview = (sevenZip, out) => {
  const header = sevenZip.startHeader || {};
  const next = sevenZip.nextHeader || {};
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">7z overview</h4>`);
  out.push(`<dl>`);
  out.push(dd("Version", `${header.versionMajor}.${header.versionMinor}`));
  out.push(dd("Start header CRC", toHex32(header.startHeaderCrc, 8)));
  out.push(dd("Next header offset", formatOffset(header.absoluteNextHeaderOffset)));
  out.push(dd("Next header size", formatSize(header.nextHeaderSize)));
  out.push(dd("Next header CRC", toHex32(next.crc ?? header.nextHeaderCrc, 8)));
  out.push(dd("Header kind", safe(next.parsed?.kind || "unknown")));
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

const renderFiles = (sevenZip, out) => {
  const filesInfo = sevenZip.nextHeader?.parsed?.sections?.filesInfo;
  const files = filesInfo?.files || [];
  if (!files.length) return;
  const limit = 200;
  const shown = files.slice(0, limit);
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Files (${files.length})</h4>`);
  out.push(
    `<table class="table"><thead><tr>` +
      `<th>#</th><th>Name</th><th>Type</th><th>Modified</th><th>Attributes</th>` +
    `</tr></thead><tbody>`
  );
  shown.forEach(file => {
    const type = describeFileType(file);
    const modified = file.modifiedTime ? safe(file.modifiedTime) : "-";
    const attrs = file.attributes ? safe(file.attributes) : "-";
    out.push(
      `<tr><td>${file.index}</td><td>${safe(file.name)}</td>` +
        `<td>${safe(type)}</td><td>${modified}</td>` +
        `<td>${attrs}</td></tr>`
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
  renderFiles(sevenZip, out);
  renderIssues(sevenZip, out);
  return out.join("");
}
