"use strict";

import { formatHumanSize, toHex64 } from "../binary-utils.js";
import { rowFlags, safe } from "../html-utils.js";
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
  out.push(`<div class="smallNote" style="margin:.25rem 0 .5rem 0;padding-left:${safe(padLeft)}">`);
  out.push(
    `${safe(directoryPath)} - ${safe(String(totalEntries))} entries` +
      `, ${safe(formatHumanSize(bytesRead))} scanned` +
      (declaredSize > bytesRead ? ` <span class="dim">(declared ${safe(formatHumanSize(declaredSize))})</span>` : "")
  );
  out.push(`</div>`);

  out.push(`<table class="table"><thead><tr>`);
  out.push("<th>Name</th><th>Kind</th><th>Size</th><th>Extent</th><th>Flags</th><th>Recorded</th><th>Actions</th>");
  out.push(`</tr></thead><tbody>`);

  entries.forEach((entry, index) => {
    const name = entry.name || "(unnamed)";
    const actionCell = (() => {
      if (entry.kind === "directory") {
        if (entry.extentLocationLba == null) return `<span class="smallNote">Unavailable</span>`;
        const targetId = `${containerIdPrefix}-dir-${index}`;
        const nextPath = joinIsoPath(directoryPath, name);
        const sizeAttr = entry.dataLength != null ? ` data-iso-size="${safe(String(entry.dataLength))}"` : "";
        return (
          `<button type="button" class="tableButton isoDirToggleButton" data-iso-action="toggle-dir"` +
            ` data-iso-lba="${safe(String(entry.extentLocationLba))}"${sizeAttr}` +
            ` data-iso-path="${safe(nextPath)}" data-iso-depth="${safe(String(depth + 1))}"` +
            ` data-iso-target="${safe(targetId)}">Expand</button>`
        );
      }
      if (entry.kind !== "file") return `<span class="smallNote">-</span>`;
      if (entry.extentLocationLba == null || entry.dataLength == null) return `<span class="smallNote">Unavailable</span>`;
      if ((entry.fileFlags & 0x80) !== 0) return `<span class="smallNote">Multi-extent</span>`;
      const offset = entry.extentLocationLba * isoBlockSize;
      return (
        `<button type="button" class="tableButton isoExtractButton" data-iso-action="extract"` +
          ` data-iso-offset="${safe(String(offset))}" data-iso-length="${safe(String(entry.dataLength))}"` +
          ` data-iso-name="${safe(name)}" data-iso-flags="${safe(String(entry.fileFlags))}">Download</button>`
      );
    })();

    const childTarget =
      entry.kind === "directory" && entry.extentLocationLba != null ? `${containerIdPrefix}-dir-${index}` : null;

    out.push(
      "<tr>" +
        `<td style="padding-left:${safe(padLeft)}">${safe(name)}</td>` +
        `<td>${safe(entry.kind)}</td>` +
        `<td>${safe(entry.dataLength != null ? formatHumanSize(entry.dataLength) : "-")}</td>` +
        `<td>${safe(formatLbaWithOffset(entry.extentLocationLba, isoBlockSize))}</td>` +
        `<td>${rowFlags(entry.fileFlags, FILE_FLAGS)}</td>` +
        `<td>${safe(entry.recordingDateTime || "-")}</td>` +
        `<td>${actionCell}</td>` +
      "</tr>"
    );
    if (childTarget) {
      out.push(
        `<tr hidden><td colspan="7">` +
          `<div id="${safe(childTarget)}" class="isoDirChildren" data-iso-loaded="0"></div>` +
        `</td></tr>`
      );
    }
  });

  out.push(`</tbody></table>`);
  if (omittedEntries) {
    out.push(`<div class="smallNote">${safe(String(omittedEntries))} more entries not shown.</div>`);
  }
  if (issues.length) {
    out.push(`<div class="smallNote" style="margin-top:.5rem">Notices:</div>`);
    out.push(`<ul class="issueList">`);
    issues.forEach(issue => out.push(`<li>${safe(issue)}</li>`));
    out.push(`</ul>`);
  }
  return out.join("");
};

export { renderIso9660DirectoryListing };
