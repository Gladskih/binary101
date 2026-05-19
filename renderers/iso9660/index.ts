"use strict";

import { formatHumanSize, toHex32, toHex64 } from "../../binary-utils.js";
import { renderDefinitionRow, renderFlagChips, escapeHtml } from "../../html-utils.js";
import type {
  Iso9660DirectoryEntrySummary,
  Iso9660ParseResult,
  Iso9660PathTableEntry,
  Iso9660PrimaryVolumeDescriptor,
  Iso9660SupplementaryVolumeDescriptor
} from "../../analyzers/iso9660/types.js";

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

const formatLba = (lba: number | null | undefined, blockSize: number): string => {
  if (lba == null) return "-";
  const offset = BigInt(lba) * BigInt(blockSize);
  return `${lba} (${toHex64(offset)})`;
};

const formatBlocksSize = (blocks: number | null | undefined, blockSize: number): string => {
  if (blocks == null) return "-";
  const bytes = blocks * blockSize;
  return `${blocks} blocks (${escapeHtml(formatHumanSize(bytes))})`;
};

const renderDescriptors = (iso: Iso9660ParseResult, out: string[]): void => {
  if (!iso.descriptors.length) return;
  out.push("<section>");
  out.push('<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Volume descriptors</h4>');
  out.push('<table class="table"><thead><tr>');
  out.push("<th>#</th><th>Type</th><th>Sector</th><th>Offset</th>");
  out.push("</tr></thead><tbody>");
  iso.descriptors.forEach((d, index) => {
    out.push(
      "<tr>" +
        `<td>${index}</td>` +
        `<td>${escapeHtml(d.typeName)}</td>` +
        `<td>${escapeHtml(String(d.sector))}</td>` +
        `<td>${escapeHtml(toHex32(d.byteOffset >>> 0, 8))}</td>` +
      "</tr>"
    );
  });
  out.push("</tbody></table>");
  out.push("</section>");
};

const renderVolumeDescriptor = (
  label: string,
  vd: Iso9660PrimaryVolumeDescriptor | Iso9660SupplementaryVolumeDescriptor | null,
  out: string[],
  opts?: { encoding?: string; escapeSequences?: string | null }
): void => {
  if (!vd) return;
  out.push("<section>");
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">${escapeHtml(label)}</h4>`);
  out.push("<dl>");
  if (opts?.encoding) out.push(renderDefinitionRow("Encoding", escapeHtml(opts.encoding)));
  if (opts?.escapeSequences != null) out.push(renderDefinitionRow("Escape sequences", escapeHtml(opts.escapeSequences || "-")));
  out.push(renderDefinitionRow("System identifier", escapeHtml(vd.systemIdentifier || "-")));
  out.push(renderDefinitionRow("Volume identifier", escapeHtml(vd.volumeIdentifier || "-")));
  out.push(renderDefinitionRow("Volume space size", formatBlocksSize(vd.volumeSpaceSizeBlocks, vd.logicalBlockSize || 2048)));
  out.push(renderDefinitionRow("Logical block size", escapeHtml(vd.logicalBlockSize != null ? `${vd.logicalBlockSize} bytes` : "-")));
  out.push(renderDefinitionRow("Path table size", escapeHtml(vd.pathTableSize != null ? `${vd.pathTableSize} bytes` : "-")));
  out.push(renderDefinitionRow("Type L path table", escapeHtml(vd.typeLPathTableLocation != null ? String(vd.typeLPathTableLocation) : "-")));
  out.push(renderDefinitionRow("Root directory extent", escapeHtml(formatLba(vd.rootDirectoryRecord?.extentLocationLba ?? null, vd.logicalBlockSize || 2048))));
  out.push(renderDefinitionRow("Root directory size", escapeHtml(vd.rootDirectoryRecord?.dataLength != null ? formatHumanSize(vd.rootDirectoryRecord.dataLength) : "-")));
  out.push(renderDefinitionRow("Publisher", escapeHtml(vd.publisherIdentifier || "-")));
  out.push(renderDefinitionRow("Data preparer", escapeHtml(vd.dataPreparerIdentifier || "-")));
  out.push(renderDefinitionRow("Application", escapeHtml(vd.applicationIdentifier || "-")));
  out.push(renderDefinitionRow("Created", escapeHtml(vd.volumeCreationDateTime || "-")));
  out.push(renderDefinitionRow("Modified", escapeHtml(vd.volumeModificationDateTime || "-")));
  out.push(renderDefinitionRow("Expires", escapeHtml(vd.volumeExpirationDateTime || "-")));
  out.push(renderDefinitionRow("Effective", escapeHtml(vd.volumeEffectiveDateTime || "-")));
  out.push("</dl>");
  out.push("</section>");
};

const renderBootRecords = (iso: Iso9660ParseResult, out: string[]): void => {
  if (!iso.bootRecords.length) return;
  out.push("<section>");
  out.push('<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Boot records</h4>');
  out.push("<dl>");
  const first = iso.bootRecords[0];
  out.push(renderDefinitionRow("Count", escapeHtml(String(iso.bootRecords.length))));
  out.push(renderDefinitionRow("Boot system identifier", escapeHtml(first?.bootSystemIdentifier || "-")));
  out.push(renderDefinitionRow("Boot identifier", escapeHtml(first?.bootIdentifier || "-")));
  out.push(renderDefinitionRow("El Torito catalog LBA", escapeHtml(first?.elToritoCatalogLba != null ? String(first.elToritoCatalogLba) : "-")));
  out.push("</dl>");
  out.push("</section>");
};

const renderPathTable = (iso: Iso9660ParseResult, out: string[]): void => {
  const pathTable = iso.pathTable;
  if (!pathTable) return;
  out.push("<section>");
  out.push('<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Path table (Type L)</h4>');
  out.push("<dl>");
  out.push(renderDefinitionRow("Location (LBA)", escapeHtml(pathTable.locationLba != null ? String(pathTable.locationLba) : "-")));
  out.push(renderDefinitionRow("Declared size", escapeHtml(pathTable.declaredSize != null ? formatHumanSize(pathTable.declaredSize) : "-")));
  out.push(renderDefinitionRow("Bytes scanned", escapeHtml(formatHumanSize(pathTable.bytesRead))));
  out.push(renderDefinitionRow("Entries (parsed)", escapeHtml(String(pathTable.entryCount))));
  out.push("</dl>");

  if (pathTable.entries.length) {
    out.push('<table class="table"><thead><tr>');
    out.push("<th>#</th><th>Name</th><th>Extent LBA</th><th>Parent #</th>");
    out.push("</tr></thead><tbody>");
    pathTable.entries.forEach((entry: Iso9660PathTableEntry) => {
      out.push(
        "<tr>" +
          `<td>${escapeHtml(String(entry.index))}</td>` +
          `<td>${escapeHtml(entry.identifier || "(unnamed)")}</td>` +
          `<td>${escapeHtml(entry.extentLocationLba != null ? String(entry.extentLocationLba) : "-")}</td>` +
          `<td>${escapeHtml(entry.parentDirectoryIndex != null ? String(entry.parentDirectoryIndex) : "-")}</td>` +
        "</tr>"
      );
    });
    out.push("</tbody></table>");
    if (pathTable.omittedEntries) {
      out.push(`<div class="smallNote">${escapeHtml(String(pathTable.omittedEntries))} more entries not shown.</div>`);
    }
  }
  out.push("</section>");
};

const renderRootDirectory = (iso: Iso9660ParseResult, out: string[]): void => {
  const root = iso.rootDirectory;
  if (!root) return;
  out.push("<section>");
  out.push('<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Root directory</h4>');
  out.push("<dl>");
  out.push(renderDefinitionRow("Extent", escapeHtml(formatLba(root.extentLocationLba, iso.selectedBlockSize))));
  out.push(renderDefinitionRow("Declared size", escapeHtml(root.declaredSize != null ? formatHumanSize(root.declaredSize) : "-")));
  out.push(renderDefinitionRow("Bytes scanned", escapeHtml(formatHumanSize(root.bytesRead))));
  out.push(renderDefinitionRow("Entries (parsed)", escapeHtml(String(root.totalEntries))));
  out.push("</dl>");

  if (root.entries.length) {
    out.push('<table class="table"><thead><tr>');
    out.push("<th>Name</th><th>Kind</th><th>Size</th><th>Extent</th><th>Flags</th><th>Recorded</th><th>Extract</th>");
    out.push("</tr></thead><tbody>");
    const renderExtractAction = (entry: Iso9660DirectoryEntrySummary, index: number): string => {
      if (entry.kind === "directory") {
        if (entry.extentLocationLba == null) return "<span class=\"smallNote\">Unavailable</span>";
        const targetId = `isoDir-${index}`;
        const path = entry.name ? `/${entry.name}` : "/";
        const sizeAttr = entry.dataLength != null ? ` data-iso-size="${escapeHtml(String(entry.dataLength))}"` : "";
        return (
          `<button type="button" class="tableButton isoDirToggleButton" data-iso-action="toggle-dir"` +
            ` data-iso-lba="${escapeHtml(String(entry.extentLocationLba))}"${sizeAttr}` +
            ` data-iso-path="${escapeHtml(path)}" data-iso-depth="0" data-iso-target="${escapeHtml(targetId)}">Expand</button>`
        );
      }
      if (entry.kind !== "file") return "<span class=\"smallNote\">-</span>";
      if (entry.extentLocationLba == null || entry.dataLength == null) {
        return "<span class=\"smallNote\">Unavailable</span>";
      }
      if ((entry.fileFlags & 0x80) !== 0) {
        return "<span class=\"smallNote\">Multi-extent</span>";
      }
      return (
        `<button type="button" class="tableButton isoExtractButton" data-iso-action="extract"` +
          ` data-iso-entry="${escapeHtml(String(index))}">Download</button>`
      );
    };
    root.entries.forEach((entry: Iso9660DirectoryEntrySummary, index: number) => {
      const childRowTarget = entry.kind === "directory" && entry.extentLocationLba != null ? `isoDir-${index}` : null;
      out.push(
        "<tr>" +
          `<td>${escapeHtml(entry.name || "(unnamed)")}</td>` +
          `<td>${escapeHtml(entry.kind)}</td>` +
          `<td>${escapeHtml(entry.dataLength != null ? formatHumanSize(entry.dataLength) : "-")}</td>` +
          `<td>${escapeHtml(formatLba(entry.extentLocationLba, iso.selectedBlockSize))}</td>` +
          `<td>${renderFlagChips(entry.fileFlags, FILE_FLAGS)}</td>` +
          `<td>${escapeHtml(entry.recordingDateTime || "-")}</td>` +
          `<td>${renderExtractAction(entry, index)}</td>` +
        "</tr>"
      );
      if (childRowTarget) {
        out.push(
          `<tr hidden><td colspan="7">` +
            `<div id="${escapeHtml(childRowTarget)}" class="isoDirChildren" data-iso-loaded="0"></div>` +
          `</td></tr>`
        );
      }
    });
    out.push("</tbody></table>");
    if (root.omittedEntries) {
      out.push(`<div class="smallNote">${escapeHtml(String(root.omittedEntries))} more entries not shown.</div>`);
    }
  }
  out.push("</section>");
};

const renderTraversal = (iso: Iso9660ParseResult, out: string[]): void => {
  const traversal = iso.traversal;
  if (!traversal) return;
  out.push("<section>");
  out.push('<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Directory traversal</h4>');
  out.push("<dl>");
  out.push(renderDefinitionRow("Directories scanned", escapeHtml(String(traversal.scannedDirectories))));
  out.push(renderDefinitionRow("Files scanned", escapeHtml(String(traversal.scannedFiles))));
  out.push(renderDefinitionRow("Max depth", escapeHtml(String(traversal.maxDepth))));
  out.push(renderDefinitionRow("Loop detections", escapeHtml(String(traversal.loopDetections))));
  if (traversal.omittedDirectories) out.push(renderDefinitionRow("Directories omitted", escapeHtml(String(traversal.omittedDirectories))));
  out.push("</dl>");
  out.push("</section>");
};

const renderIssues = (iso: Iso9660ParseResult, out: string[]): void => {
  const issues = iso.issues || [];
  if (!issues.length) return;
  out.push("<section>");
  out.push('<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4>');
  out.push("<ul>");
  issues.forEach(issue => out.push(`<li>${escapeHtml(issue)}</li>`));
  out.push("</ul>");
  out.push("</section>");
};

export const renderIso9660 = (iso: Iso9660ParseResult | null): string => {
  if (!iso) return "";
  const out: string[] = [];
  const selectedJoliet = iso.supplementaryVolumes.find(svd => svd.isJoliet) || null;
  const selected = iso.selectedEncoding === "ucs2be" ? selectedJoliet : iso.primaryVolume;

  out.push("<section>");
  out.push('<h4 style="margin:0 0 .5rem 0;font-size:.9rem">ISO-9660 overview</h4>');
  out.push("<dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(iso.fileSize))));
  out.push(renderDefinitionRow("Selected encoding", escapeHtml(iso.selectedEncoding)));
  out.push(renderDefinitionRow("Logical block size", escapeHtml(`${iso.selectedBlockSize} bytes`)));
  if (selected?.volumeIdentifier) out.push(renderDefinitionRow("Volume identifier", escapeHtml(selected.volumeIdentifier)));
  if (selected?.systemIdentifier) out.push(renderDefinitionRow("System identifier", escapeHtml(selected.systemIdentifier)));
  if (selected?.volumeSpaceSizeBlocks != null) {
    out.push(renderDefinitionRow("Volume space", formatBlocksSize(selected.volumeSpaceSizeBlocks, iso.selectedBlockSize)));
  }
  out.push(renderDefinitionRow("Volume partitions", escapeHtml(String(iso.volumePartitionDescriptorCount))));
  out.push("</dl>");
  out.push("</section>");

  renderDescriptors(iso, out);
  renderVolumeDescriptor("Primary Volume Descriptor", iso.primaryVolume, out, { encoding: "ASCII" });
  if (selectedJoliet) {
    const encoding = selectedJoliet.isJoliet ? `Joliet (level ${selectedJoliet.jolietLevel ?? "?"})` : "Supplementary";
    renderVolumeDescriptor("Supplementary Volume Descriptor", selectedJoliet, out, {
      encoding,
      escapeSequences: selectedJoliet.escapeSequences
    });
  }
  renderBootRecords(iso, out);
  renderPathTable(iso, out);
  renderRootDirectory(iso, out);
  renderTraversal(iso, out);
  renderIssues(iso, out);

  return out.join("");
};
