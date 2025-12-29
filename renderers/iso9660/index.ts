"use strict";

import { formatHumanSize, toHex32, toHex64 } from "../../binary-utils.js";
import { dd, rowFlags, safe } from "../../html-utils.js";
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
  return `${blocks} blocks (${safe(formatHumanSize(bytes))})`;
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
        `<td>${safe(d.typeName)}</td>` +
        `<td>${safe(String(d.sector))}</td>` +
        `<td>${safe(toHex32(d.byteOffset >>> 0, 8))}</td>` +
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
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">${safe(label)}</h4>`);
  out.push("<dl>");
  if (opts?.encoding) out.push(dd("Encoding", safe(opts.encoding)));
  if (opts?.escapeSequences != null) out.push(dd("Escape sequences", safe(opts.escapeSequences || "-")));
  out.push(dd("System identifier", safe(vd.systemIdentifier || "-")));
  out.push(dd("Volume identifier", safe(vd.volumeIdentifier || "-")));
  out.push(dd("Volume space size", formatBlocksSize(vd.volumeSpaceSizeBlocks, vd.logicalBlockSize || 2048)));
  out.push(dd("Logical block size", safe(vd.logicalBlockSize != null ? `${vd.logicalBlockSize} bytes` : "-")));
  out.push(dd("Path table size", safe(vd.pathTableSize != null ? `${vd.pathTableSize} bytes` : "-")));
  out.push(dd("Type L path table", safe(vd.typeLPathTableLocation != null ? String(vd.typeLPathTableLocation) : "-")));
  out.push(dd("Root directory extent", safe(formatLba(vd.rootDirectoryRecord?.extentLocationLba ?? null, vd.logicalBlockSize || 2048))));
  out.push(dd("Root directory size", safe(vd.rootDirectoryRecord?.dataLength != null ? formatHumanSize(vd.rootDirectoryRecord.dataLength) : "-")));
  out.push(dd("Publisher", safe(vd.publisherIdentifier || "-")));
  out.push(dd("Data preparer", safe(vd.dataPreparerIdentifier || "-")));
  out.push(dd("Application", safe(vd.applicationIdentifier || "-")));
  out.push(dd("Created", safe(vd.volumeCreationDateTime || "-")));
  out.push(dd("Modified", safe(vd.volumeModificationDateTime || "-")));
  out.push(dd("Expires", safe(vd.volumeExpirationDateTime || "-")));
  out.push(dd("Effective", safe(vd.volumeEffectiveDateTime || "-")));
  out.push("</dl>");
  out.push("</section>");
};

const renderBootRecords = (iso: Iso9660ParseResult, out: string[]): void => {
  if (!iso.bootRecords.length) return;
  out.push("<section>");
  out.push('<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Boot records</h4>');
  out.push("<dl>");
  const first = iso.bootRecords[0];
  out.push(dd("Count", safe(String(iso.bootRecords.length))));
  out.push(dd("Boot system identifier", safe(first?.bootSystemIdentifier || "-")));
  out.push(dd("Boot identifier", safe(first?.bootIdentifier || "-")));
  out.push(dd("El Torito catalog LBA", safe(first?.elToritoCatalogLba != null ? String(first.elToritoCatalogLba) : "-")));
  out.push("</dl>");
  out.push("</section>");
};

const renderPathTable = (iso: Iso9660ParseResult, out: string[]): void => {
  const pathTable = iso.pathTable;
  if (!pathTable) return;
  out.push("<section>");
  out.push('<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Path table (Type L)</h4>');
  out.push("<dl>");
  out.push(dd("Location (LBA)", safe(pathTable.locationLba != null ? String(pathTable.locationLba) : "-")));
  out.push(dd("Declared size", safe(pathTable.declaredSize != null ? formatHumanSize(pathTable.declaredSize) : "-")));
  out.push(dd("Bytes scanned", safe(formatHumanSize(pathTable.bytesRead))));
  out.push(dd("Entries (parsed)", safe(String(pathTable.entryCount))));
  out.push("</dl>");

  if (pathTable.entries.length) {
    out.push('<table class="table"><thead><tr>');
    out.push("<th>#</th><th>Name</th><th>Extent LBA</th><th>Parent #</th>");
    out.push("</tr></thead><tbody>");
    pathTable.entries.forEach((entry: Iso9660PathTableEntry) => {
      out.push(
        "<tr>" +
          `<td>${safe(String(entry.index))}</td>` +
          `<td>${safe(entry.identifier || "(unnamed)")}</td>` +
          `<td>${safe(entry.extentLocationLba != null ? String(entry.extentLocationLba) : "-")}</td>` +
          `<td>${safe(entry.parentDirectoryIndex != null ? String(entry.parentDirectoryIndex) : "-")}</td>` +
        "</tr>"
      );
    });
    out.push("</tbody></table>");
    if (pathTable.omittedEntries) {
      out.push(`<div class="smallNote">${safe(String(pathTable.omittedEntries))} more entries not shown.</div>`);
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
  out.push(dd("Extent", safe(formatLba(root.extentLocationLba, iso.selectedBlockSize))));
  out.push(dd("Declared size", safe(root.declaredSize != null ? formatHumanSize(root.declaredSize) : "-")));
  out.push(dd("Bytes scanned", safe(formatHumanSize(root.bytesRead))));
  out.push(dd("Entries (parsed)", safe(String(root.totalEntries))));
  out.push("</dl>");

  if (root.entries.length) {
    out.push('<table class="table"><thead><tr>');
    out.push("<th>Name</th><th>Kind</th><th>Size</th><th>Extent</th><th>Flags</th><th>Recorded</th><th>Extract</th>");
    out.push("</tr></thead><tbody>");
    const renderExtractAction = (entry: Iso9660DirectoryEntrySummary, index: number): string => {
      if (entry.kind !== "file") return "<span class=\"smallNote\">-</span>";
      if (entry.extentLocationLba == null || entry.dataLength == null) {
        return "<span class=\"smallNote\">Unavailable</span>";
      }
      if ((entry.fileFlags & 0x80) !== 0) {
        return "<span class=\"smallNote\">Multi-extent</span>";
      }
      return (
        `<button type="button" class="tableButton isoExtractButton" data-iso-action="extract"` +
          ` data-iso-entry="${safe(String(index))}">Download</button>`
      );
    };
    root.entries.forEach((entry: Iso9660DirectoryEntrySummary, index: number) => {
      out.push(
        "<tr>" +
          `<td>${safe(entry.name || "(unnamed)")}</td>` +
          `<td>${safe(entry.kind)}</td>` +
          `<td>${safe(entry.dataLength != null ? formatHumanSize(entry.dataLength) : "-")}</td>` +
          `<td>${safe(formatLba(entry.extentLocationLba, iso.selectedBlockSize))}</td>` +
          `<td>${rowFlags(entry.fileFlags, FILE_FLAGS)}</td>` +
          `<td>${safe(entry.recordingDateTime || "-")}</td>` +
          `<td>${renderExtractAction(entry, index)}</td>` +
        "</tr>"
      );
    });
    out.push("</tbody></table>");
    if (root.omittedEntries) {
      out.push(`<div class="smallNote">${safe(String(root.omittedEntries))} more entries not shown.</div>`);
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
  out.push(dd("Directories scanned", safe(String(traversal.scannedDirectories))));
  out.push(dd("Files scanned", safe(String(traversal.scannedFiles))));
  out.push(dd("Max depth", safe(String(traversal.maxDepth))));
  out.push(dd("Loop detections", safe(String(traversal.loopDetections))));
  if (traversal.omittedDirectories) out.push(dd("Directories omitted", safe(String(traversal.omittedDirectories))));
  out.push("</dl>");
  out.push("</section>");
};

const renderIssues = (iso: Iso9660ParseResult, out: string[]): void => {
  const issues = iso.issues || [];
  if (!issues.length) return;
  out.push("<section>");
  out.push('<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4>');
  out.push("<ul>");
  issues.forEach(issue => out.push(`<li>${safe(issue)}</li>`));
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
  out.push(dd("File size", safe(formatHumanSize(iso.fileSize))));
  out.push(dd("Selected encoding", safe(iso.selectedEncoding)));
  out.push(dd("Logical block size", safe(`${iso.selectedBlockSize} bytes`)));
  if (selected?.volumeIdentifier) out.push(dd("Volume identifier", safe(selected.volumeIdentifier)));
  if (selected?.systemIdentifier) out.push(dd("System identifier", safe(selected.systemIdentifier)));
  if (selected?.volumeSpaceSizeBlocks != null) {
    out.push(dd("Volume space", formatBlocksSize(selected.volumeSpaceSizeBlocks, iso.selectedBlockSize)));
  }
  out.push(dd("Volume partitions", safe(String(iso.volumePartitionDescriptorCount))));
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
