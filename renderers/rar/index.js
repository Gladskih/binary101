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

const formatFlags = entry => {
  const bits = [];
  if (entry.isDirectory) bits.push("Dir");
  if (entry.isSolid) bits.push("Solid");
  if (entry.isEncrypted) bits.push("Encrypted");
  if (entry.isSplitBefore || entry.isSplitAfter) bits.push("Split");
  if (entry.isInherited) bits.push("Inherited");
  if (entry.isChild) bits.push("Child");
  return bits.length ? bits.join(", ") : "-";
};

const renderSummary = (rar, out) => {
  const count = rar.entries?.length || 0;
  const main = rar.mainHeader || {};
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">RAR overview</h4>`);
  out.push(`<dl>`);
  out.push(dd("Version", safe(rar.version || "-")));
  out.push(dd("Entries", count.toString()));
  out.push(dd("Solid archive", main.isSolid ? "Yes" : "No"));
  out.push(dd("Volume", main.isVolume ? "Yes" : "No"));
  out.push(dd("Recovery record", main.hasRecovery ? "Yes" : "No"));
  out.push(dd("Locked", main.isLocked ? "Yes" : "No"));
  out.push(dd("First volume", main.isFirstVolume ? "Yes" : "No"));
  out.push(`</dl>`);
  out.push(`</section>`);
};

const renderEntries = (rar, out) => {
  const entries = rar.entries || [];
  if (!entries.length) return;
  const limit = 200;
  const list = entries.slice(0, limit);
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">File entries</h4>`);
  out.push(
    `<table class="table"><thead><tr>` +
      `<th>#</th><th>Name</th><th>Packed</th><th>Unpacked</th>` +
      `<th>Method</th><th>Host</th><th>Flags</th><th>Modified</th>` +
    `</tr></thead><tbody>`
  );
  list.forEach(entry => {
    const packed = formatSize(entry.packSize);
    const unpacked = formatSize(entry.unpackedSize);
    const flags = formatFlags(entry);
    const crc = entry.crc32 != null ? toHex32(entry.crc32, 8) : "-";
    const modified = safe(entry.modified || "-");
    out.push(
      `<tr><td>${entry.index ?? ""}</td>` +
        `<td>${safe(entry.name || "(unnamed)")}</td>` +
        `<td>${packed}</td><td>${unpacked}</td>` +
        `<td>${safe(entry.method || "-")}</td>` +
        `<td>${safe(entry.hostOs || "-")}</td>` +
        `<td>${safe(flags)}</td>` +
        `<td>${modified}<br/><span class="smallNote">CRC ${crc}</span></td>` +
      `</tr>`
    );
  });
  out.push(`</tbody></table>`);
  if (entries.length > limit) {
    const more = entries.length - limit;
    out.push(`<div class="smallNote">${more} more entries not shown.</div>`);
  }
  out.push(`</section>`);
};

const renderIssues = (rar, out) => {
  const issues = rar.issues || [];
  if (!issues.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4>`);
  out.push(`<ul>`);
  issues.forEach(issue => out.push(`<li>${safe(issue)}</li>`));
  out.push(`</ul>`);
  out.push(`</section>`);
};

export function renderRar(rar) {
  if (!rar) return "";
  const out = [];
  renderSummary(rar, out);
  renderEntries(rar, out);
  renderIssues(rar, out);
  return out.join("");
}
