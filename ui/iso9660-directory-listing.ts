"use strict";

import { formatHumanSize, toHex64 } from "../binary-utils.js";
import { renderFlagChips, escapeHtml } from "../html-utils.js";
import type { Iso9660DirectoryEntrySummary } from "../analyzers/iso9660/types.js";

const FILE_FLAGS: Array<[number, string, string]> = [
  [0x01, "Hidden", "Should not appear in directory listings"],
  [0x02, "Directory", "Entry points to a directory extent"],
  [0x04, "Associated", "Associated file"],
  [0x08, "Record", "Record format is specified"],
  [0x10, "Protection", "Owner/group permissions are specified"],
  [0x20, "Reserved", "Reserved by ISO-9660"],
  [0x40, "Reserved", "Reserved by ISO-9660"],
  [0x80, "Multi-extent", "Not the final directory record for this file"]
];

const joinIsoPath = (parent: string, child: string): string => {
  const trimmedParent = parent.trim();
  const trimmedChild = child.trim();
  if (!trimmedParent || trimmedParent === "/") return `/${trimmedChild}`;
  if (!trimmedChild.length) return trimmedParent;
  if (trimmedParent.endsWith("/")) return `${trimmedParent}${trimmedChild}`;
  return `${trimmedParent}/${trimmedChild}`;
};

const formatLbaWithOffset = (lba: number | null | undefined, blockSize: number): string => {
  if (lba == null) return "-";
  const offset = BigInt(lba) * BigInt(blockSize);
  return `${lba} (${toHex64(offset)})`;
};

const renderDirectoryAction = (
  entry: Iso9660DirectoryEntrySummary,
  name: string,
  index: number,
  directoryPath: string,
  depth: number,
  containerIdPrefix: string
): string => {
  if (entry.extentLocationLba == null) return `<span class="smallNote">Unavailable</span>`;
  const targetId = `${containerIdPrefix}-dir-${index}`;
  const sizeAttr = entry.dataLength != null ? ` data-iso-size="${escapeHtml(String(entry.dataLength))}"` : "";
  return (
    `<button type="button" class="tableButton isoDirToggleButton" data-iso-action="toggle-dir"` +
      ` data-iso-lba="${escapeHtml(String(entry.extentLocationLba))}"${sizeAttr}` +
      ` data-iso-path="${escapeHtml(joinIsoPath(directoryPath, name))}"` +
      ` data-iso-depth="${escapeHtml(String(depth + 1))}"` +
      ` data-iso-target="${escapeHtml(targetId)}">Expand</button>`
  );
};

const renderFileAction = (
  entry: Iso9660DirectoryEntrySummary,
  name: string,
  isoBlockSize: number
): string => {
  if (entry.extentLocationLba == null || entry.dataLength == null) {
    return `<span class="smallNote">Unavailable</span>`;
  }
  if ((entry.fileFlags & 0x80) !== 0) return `<span class="smallNote">Multi-extent</span>`;
  return (
    `<button type="button" class="tableButton isoExtractButton" data-iso-action="extract"` +
      ` data-iso-offset="${escapeHtml(String(entry.extentLocationLba * isoBlockSize))}"` +
      ` data-iso-length="${escapeHtml(String(entry.dataLength))}"` +
      ` data-iso-name="${escapeHtml(name)}" data-iso-flags="${escapeHtml(String(entry.fileFlags))}">Download</button>`
  );
};

const renderEntryAction = (
  entry: Iso9660DirectoryEntrySummary,
  name: string,
  index: number,
  directoryPath: string,
  depth: number,
  isoBlockSize: number,
  containerIdPrefix: string
): string => {
  if (entry.kind === "directory") {
    return renderDirectoryAction(entry, name, index, directoryPath, depth, containerIdPrefix);
  }
  if (entry.kind !== "file") return `<span class="smallNote">-</span>`;
  return renderFileAction(entry, name, isoBlockSize);
};

const renderEntryRow = (
  entry: Iso9660DirectoryEntrySummary,
  name: string,
  actionCell: string,
  padLeft: string,
  isoBlockSize: number
): string => (
  "<tr>" +
    `<td style="padding-left:${escapeHtml(padLeft)}">${escapeHtml(name)}</td>` +
    `<td>${escapeHtml(entry.kind)}</td>` +
    `<td>${escapeHtml(entry.dataLength != null ? formatHumanSize(entry.dataLength) : "-")}</td>` +
    `<td>${escapeHtml(formatLbaWithOffset(entry.extentLocationLba, isoBlockSize))}</td>` +
    `<td>${renderFlagChips(entry.fileFlags, FILE_FLAGS)}</td>` +
    `<td>${escapeHtml(entry.recordingDateTime || "-")}</td>` +
    `<td>${actionCell}</td>` +
  "</tr>"
);

const renderIso9660DirectoryListing = (opts: {
  entries: Iso9660DirectoryEntrySummary[];
  totalEntries: number;
  omittedEntries: number;
  bytesRead: number;
  declaredSize: number;
  directoryPath: string;
  depth: number;
  isoBlockSize: number;
  containerIdPrefix: string;
  issues: string[];
}): string => {
  const {
    entries,
    totalEntries,
    omittedEntries,
    bytesRead,
    declaredSize,
    directoryPath,
    depth,
    isoBlockSize,
    containerIdPrefix,
    issues
  } = opts;

  const out: string[] = [];
  const indent = Math.min(6, Math.max(0, depth));
  const padLeft = `${indent * 12}px`;
  out.push(`<div class="smallNote" style="margin:.25rem 0 .5rem 0;padding-left:${escapeHtml(padLeft)}">`);
  out.push(
    `${escapeHtml(directoryPath)} - ${escapeHtml(String(totalEntries))} entries` +
      `, ${escapeHtml(formatHumanSize(bytesRead))} scanned` +
      (declaredSize > bytesRead ? ` <span class="dim">(declared ${escapeHtml(formatHumanSize(declaredSize))})</span>` : "")
  );
  out.push(`</div>`);

  out.push(`<table class="table"><thead><tr>`);
  out.push("<th>Name</th><th>Kind</th><th>Size</th><th>Extent</th><th>Flags</th><th>Recorded</th><th>Actions</th>");
  out.push(`</tr></thead><tbody>`);

  entries.forEach((entry, index) => {
    const name = entry.name || "(unnamed)";
    const actionCell = renderEntryAction(entry, name, index, directoryPath, depth, isoBlockSize, containerIdPrefix);
    const childTarget =
      entry.kind === "directory" && entry.extentLocationLba != null ? `${containerIdPrefix}-dir-${index}` : null;
    out.push(renderEntryRow(entry, name, actionCell, padLeft, isoBlockSize));
    if (childTarget) {
      out.push(
        `<tr hidden><td colspan="7">` +
          `<div id="${escapeHtml(childTarget)}" class="isoDirChildren" data-iso-loaded="0"></div>` +
        `</td></tr>`
      );
    }
  });

  out.push(`</tbody></table>`);
  if (omittedEntries) {
    out.push(`<div class="smallNote">${escapeHtml(String(omittedEntries))} more entries not shown.</div>`);
  }
  if (issues.length) {
    out.push(`<div class="smallNote" style="margin-top:.5rem">Notices:</div>`);
    out.push(`<ul class="issueList">`);
    issues.forEach(issue => out.push(`<li>${escapeHtml(issue)}</li>`));
    out.push(`</ul>`);
  }
  return out.join("");
};

export { renderIso9660DirectoryListing };
