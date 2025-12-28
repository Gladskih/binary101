"use strict";

import { toHex32 } from "../../binary-utils.js";
import type { Iso9660DirectoryListing, Iso9660DirectoryTraversalStats, Iso9660ParseResult, Iso9660StringEncoding } from "./types.js";
import { ISO9660_DESCRIPTOR_BLOCK_SIZE, ISO9660_SYSTEM_AREA_BLOCKS } from "./iso-parsing.js";
import { scanDirectoryBytes } from "./directory-records.js";
import { parseTypeLPathTable } from "./path-table.js";
import {
  parseBootRecordDescriptor,
  parseDescriptorSummary,
  parsePrimaryVolumeDescriptor,
  parseSupplementaryVolumeDescriptor
} from "./volume-descriptors.js";

const MAX_ISSUES = 200;
const MAX_DESCRIPTORS = 128;
const MAX_PATH_TABLE_BYTES = 4 * 1024 * 1024;
const MAX_PATH_TABLE_ENTRIES = 200;
const MAX_ROOT_ENTRIES = 200;
const MAX_DIRECTORY_BYTES = 4 * 1024 * 1024;
const MAX_SCAN_DIRECTORIES = 5000;
const MAX_SCAN_DEPTH = 64;

const formatOffsetHex = (offset: number): string => toHex32(offset >>> 0, 8);

export const hasIso9660Signature = (dv: DataView | null): boolean => {
  if (!dv) return false;
  const markers = [0x8001, 0x8801, 0x9001];
  for (const marker of markers) {
    if (dv.byteLength < marker + 5) continue;
    const text =
      String.fromCharCode(dv.getUint8(marker + 0)) +
      String.fromCharCode(dv.getUint8(marker + 1)) +
      String.fromCharCode(dv.getUint8(marker + 2)) +
      String.fromCharCode(dv.getUint8(marker + 3)) +
      String.fromCharCode(dv.getUint8(marker + 4));
    if (text === "CD001") return true;
  }
  return false;
};

const readFileBytes = async (file: File, offset: number, length: number): Promise<Uint8Array> => {
  if (offset < 0 || length <= 0 || offset >= file.size) return new Uint8Array(0);
  const end = Math.min(file.size, offset + length);
  const buffer = await file.slice(offset, end).arrayBuffer();
  return new Uint8Array(buffer);
};

export async function parseIso9660(file: File): Promise<Iso9660ParseResult | null> {
  if (!file) return null;
  const issues: string[] = [];
  let omittedIssues = false;
  const pushIssue = (message: string): void => {
    if (issues.length >= MAX_ISSUES) {
      if (!omittedIssues) {
        issues.push("Additional issues were detected but omitted to keep the report readable.");
        omittedIssues = true;
      }
      return;
    }
    issues.push(String(message));
  };

  const descriptors: Iso9660ParseResult["descriptors"] = [];
  let primaryVolume: Iso9660ParseResult["primaryVolume"] = null;
  const supplementaryVolumes: Iso9660ParseResult["supplementaryVolumes"] = [];
  const bootRecords: Iso9660ParseResult["bootRecords"] = [];
  let volumePartitionDescriptorCount = 0;
  let terminatorSector: number | null = null;

  for (let index = 0; index < MAX_DESCRIPTORS; index += 1) {
    const sector = ISO9660_SYSTEM_AREA_BLOCKS + index;
    const byteOffset = sector * ISO9660_DESCRIPTOR_BLOCK_SIZE;
    if (byteOffset + 7 > file.size) {
      pushIssue(`Truncated ISO volume descriptor at ${formatOffsetHex(byteOffset)}.`);
      break;
    }
    const bytes = await readFileBytes(file, byteOffset, ISO9660_DESCRIPTOR_BLOCK_SIZE);
    const summary = parseDescriptorSummary(bytes, sector, byteOffset);
    if (!summary) {
      pushIssue(`Unable to read volume descriptor header at ${formatOffsetHex(byteOffset)}.`);
      break;
    }
    if (summary.identifier !== "CD001") {
      pushIssue(
        `Unexpected volume descriptor identifier ${JSON.stringify(summary.identifier)} at ${formatOffsetHex(byteOffset)}.`
      );
      break;
    }
    descriptors.push(summary);

    if (summary.typeCode === 0) {
      bootRecords.push(parseBootRecordDescriptor(bytes));
    } else if (summary.typeCode === 1) {
      primaryVolume = parsePrimaryVolumeDescriptor(bytes, byteOffset, pushIssue);
    } else if (summary.typeCode === 2) {
      supplementaryVolumes.push(parseSupplementaryVolumeDescriptor(bytes, byteOffset, pushIssue));
    } else if (summary.typeCode === 3) {
      volumePartitionDescriptorCount += 1;
    } else if (summary.typeCode === 255) {
      terminatorSector = sector;
      break;
    }
  }

  if (descriptors.length === 0) return null;

  const selectedSupplementary = supplementaryVolumes.find(svd => svd.isJoliet) || null;
  const selectedVolume = selectedSupplementary || primaryVolume;
  const selectedEncoding: Iso9660StringEncoding = selectedSupplementary ? "ucs2be" : "ascii";
  let selectedBlockSize = selectedVolume?.logicalBlockSize ?? ISO9660_DESCRIPTOR_BLOCK_SIZE;
  if (!selectedBlockSize || !Number.isFinite(selectedBlockSize) || selectedBlockSize <= 0) {
    selectedBlockSize = ISO9660_DESCRIPTOR_BLOCK_SIZE;
  }
  if (selectedBlockSize !== ISO9660_DESCRIPTOR_BLOCK_SIZE) {
    pushIssue(`Unusual logical block size: ${selectedBlockSize} bytes (expected ${ISO9660_DESCRIPTOR_BLOCK_SIZE}).`);
  }

  const pathTable = await (async (): Promise<Iso9660ParseResult["pathTable"]> => {
    if (
      !selectedVolume ||
      selectedVolume.pathTableSize == null ||
      selectedVolume.typeLPathTableLocation == null
    ) {
      return null;
    }
    if (selectedVolume.pathTableSize <= 0 || selectedVolume.typeLPathTableLocation <= 0) return null;
    const pathTableOffset = selectedVolume.typeLPathTableLocation * selectedBlockSize;
    const declaredSize = selectedVolume.pathTableSize;
    const available = Math.max(0, file.size - pathTableOffset);
    const bytesToRead = Math.min(declaredSize, available, MAX_PATH_TABLE_BYTES);
    if (bytesToRead <= 0) return null;
    if (declaredSize > bytesToRead) {
      pushIssue(
        `Path table is large (${declaredSize} bytes); only first ${bytesToRead} bytes were scanned.`
      );
    }
    const bytes = await readFileBytes(file, pathTableOffset, bytesToRead);
    const parsed = parseTypeLPathTable({
      bytes,
      absoluteBaseOffset: pathTableOffset,
      encoding: selectedEncoding,
      pushIssue,
      maxEntries: MAX_PATH_TABLE_ENTRIES
    });
    return {
      locationLba: selectedVolume.typeLPathTableLocation,
      declaredSize,
      bytesRead: bytes.length,
      entryCount: parsed.entryCount,
      entries: parsed.entries,
      omittedEntries: parsed.omittedEntries
    };
  })();

  const rootDirectory = await (async (): Promise<Iso9660DirectoryListing | null> => {
    const root = selectedVolume?.rootDirectoryRecord;
    if (!root || root.extentLocationLba == null || root.dataLength == null) return null;
    const directoryOffset = root.extentLocationLba * selectedBlockSize;
    const declaredSize = root.dataLength;
    const available = Math.max(0, file.size - directoryOffset);
    const bytesToRead = Math.min(declaredSize, available, MAX_DIRECTORY_BYTES);
    if (bytesToRead <= 0) {
      pushIssue(`Root directory claims bytes past end of file at ${formatOffsetHex(directoryOffset)}.`);
      return null;
    }
    if (declaredSize > bytesToRead) {
      pushIssue(`Root directory is large (${declaredSize} bytes); only first ${bytesToRead} bytes were scanned.`);
    }
    const bytes = await readFileBytes(file, directoryOffset, bytesToRead);
    const scan = scanDirectoryBytes({
      bytes,
      absoluteBaseOffset: directoryOffset,
      blockSize: selectedBlockSize,
      encoding: selectedEncoding,
      pushIssue,
      maxEntries: MAX_ROOT_ENTRIES
    });
    return {
      extentLocationLba: root.extentLocationLba,
      byteOffset: directoryOffset,
      declaredSize,
      bytesRead: bytes.length,
      totalEntries: scan.totalEntries,
      entries: scan.entries,
      omittedEntries: scan.omittedEntries
    };
  })();

  const traversal = await (async (): Promise<Iso9660DirectoryTraversalStats | null> => {
    const root = selectedVolume?.rootDirectoryRecord;
    if (!root || root.extentLocationLba == null || root.dataLength == null) return null;

    const visited = new Set<number>();
    const stack: Array<{ lba: number; size: number; depth: number }> = [
      { lba: root.extentLocationLba, size: root.dataLength, depth: 0 }
    ];
    const stats: Iso9660DirectoryTraversalStats = {
      scannedDirectories: 0,
      scannedFiles: 0,
      maxDepth: 0,
      omittedDirectories: 0,
      omittedEntries: 0,
      loopDetections: 0
    };

    while (stack.length) {
      const next = stack.pop();
      if (!next) break;
      if (next.depth > MAX_SCAN_DEPTH) {
        stats.omittedDirectories += 1;
        continue;
      }
      if (visited.has(next.lba)) {
        stats.loopDetections += 1;
        continue;
      }
      visited.add(next.lba);
      if (stats.scannedDirectories >= MAX_SCAN_DIRECTORIES) {
        stats.omittedDirectories += stack.length + 1;
        break;
      }

      const directoryOffset = next.lba * selectedBlockSize;
      const declaredSize = next.size;
      const available = Math.max(0, file.size - directoryOffset);
      const bytesToRead = Math.min(declaredSize, available, MAX_DIRECTORY_BYTES);
      if (bytesToRead <= 0) {
        pushIssue(`Directory at LBA ${next.lba} is outside the file (offset ${formatOffsetHex(directoryOffset)}).`);
        stats.omittedDirectories += 1;
        continue;
      }
      const bytes = await readFileBytes(file, directoryOffset, bytesToRead);
      const scan = scanDirectoryBytes({
        bytes,
        absoluteBaseOffset: directoryOffset,
        blockSize: selectedBlockSize,
        encoding: selectedEncoding,
        pushIssue,
        maxEntries: 0
      });
      stats.scannedDirectories += 1;
      stats.scannedFiles += scan.fileCount;
      stats.maxDepth = Math.max(stats.maxDepth, next.depth);
      if (declaredSize > bytesToRead) stats.omittedEntries += 1;

      for (const child of scan.childDirectories) {
        const childSize = child.dataLength ?? selectedBlockSize;
        stack.push({ lba: child.extentLocationLba, size: childSize, depth: next.depth + 1 });
      }
    }

    return stats;
  })();

  const parsed: Iso9660ParseResult = {
    isIso9660: true,
    fileSize: file.size,
    descriptorBlockSize: ISO9660_DESCRIPTOR_BLOCK_SIZE,
    descriptors,
    primaryVolume,
    supplementaryVolumes,
    bootRecords,
    volumePartitionDescriptorCount,
    terminatorSector,
    selectedEncoding,
    selectedBlockSize,
    pathTable,
    rootDirectory,
    traversal,
    issues
  };
  return parsed;
}
