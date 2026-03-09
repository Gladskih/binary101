"use strict";

// Range semantics for Mach-O segments, sections, relocation entries, dyld info,
// linkedit_data_command, encryption_info_command(_64), and fileset_entry_command
// come from Apple's public Mach-O headers:
// https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/loader.h

import { loadCommandName } from "./load-command-info.js";
import type {
  MachODyldInfo,
  MachOEncryptionInfo,
  MachOFileSetEntry,
  MachOLinkeditData,
  MachOSegment,
  MachOSection
} from "./types.js";

const RELOCATION_INFO_SIZE = 8n;

const isBigIntRangeWithin = (limit: number, offset: bigint, size: bigint): boolean => {
  const bigLimit = BigInt(limit);
  return offset >= 0n && size >= 0n && offset <= bigLimit && size <= bigLimit - offset;
};

const hasFileBackedSectionData = (section: MachOSection): boolean => {
  const sectionType = section.flags & 0xff;
  // Zero-fill section kinds in mach-o/loader.h do not occupy file bytes.
  return sectionType !== 0x01 && sectionType !== 0x0c && sectionType !== 0x12;
};

const isRangeWithinRange = (
  outerOffset: bigint,
  outerSize: bigint,
  innerOffset: bigint,
  innerSize: bigint
): boolean =>
  outerOffset >= 0n &&
  outerSize >= 0n &&
  innerOffset >= outerOffset &&
  innerSize >= 0n &&
  innerOffset <= outerOffset + outerSize &&
  innerSize <= outerOffset + outerSize - innerOffset;

const validateSectionRanges = (
  segment: MachOSegment,
  imageSize: number,
  issues: string[]
): void => {
  for (const section of segment.sections) {
    const segmentName = segment.name || "<unnamed>";
    const sectionName = section.sectionName || "<unnamed>";
    if (
      hasFileBackedSectionData(section) &&
      section.size > 0n &&
      !isBigIntRangeWithin(imageSize, BigInt(section.offset), section.size)
    ) {
      issues.push(
        `Load command ${segment.loadCommandIndex}: section ${segmentName},` +
          `${sectionName} data range (${section.offset}, ${section.size}) ` +
          `extends beyond the Mach-O image.`
      );
    }
    if (
      hasFileBackedSectionData(section) &&
      section.size > 0n &&
      !isRangeWithinRange(segment.fileoff, segment.filesize, BigInt(section.offset), section.size)
    ) {
      issues.push(
        `Load command ${segment.loadCommandIndex}: section ${segmentName},${sectionName} ` +
          `file range (${section.offset}, ${section.size}) extends beyond segment ${segmentName} ` +
          `file range (${segment.fileoff}, ${segment.filesize}).`
      );
    }
    if (
      section.size > 0n &&
      !isRangeWithinRange(segment.vmaddr, segment.vmsize, section.addr, section.size)
    ) {
      issues.push(
        `Load command ${segment.loadCommandIndex}: section ${segmentName},${sectionName} ` +
          `VM range (${section.addr}, ${section.size}) extends beyond segment ${segmentName} ` +
          `VM range (${segment.vmaddr}, ${segment.vmsize}).`
      );
    }
    if (
      section.nreloc > 0 &&
      !isBigIntRangeWithin(
        imageSize,
        BigInt(section.reloff),
        BigInt(section.nreloc) * RELOCATION_INFO_SIZE
      )
    ) {
      issues.push(
        `Load command ${segment.loadCommandIndex}: section ${segmentName},` +
          `${sectionName} relocation range (${section.reloff}, ` +
          `${BigInt(section.nreloc) * RELOCATION_INFO_SIZE}) extends beyond the Mach-O image.`
      );
    }
  }
};

const validateSegmentRanges = (
  segments: MachOSegment[],
  imageSize: number,
  issues: string[]
): void => {
  for (const segment of segments) {
    if (segment.filesize > segment.vmsize) {
      issues.push(
        `Load command ${segment.loadCommandIndex}: segment ${segment.name || "<unnamed>"} ` +
          `filesize ${segment.filesize} exceeds vmsize ${segment.vmsize}.`
      );
    }
    if (
      segment.filesize > 0n &&
      !isBigIntRangeWithin(imageSize, segment.fileoff, segment.filesize)
    ) {
      issues.push(
        `Load command ${segment.loadCommandIndex}: segment ${segment.name || "<unnamed>"} ` +
          `file range (${segment.fileoff}, ${segment.filesize}) extends beyond the Mach-O image.`
      );
    }
    validateSectionRanges(segment, imageSize, issues);
  }
};

const validateDyldInfoRanges = (
  dyldInfo: MachODyldInfo | null,
  imageSize: number,
  issues: string[]
): void => {
  if (!dyldInfo) return;
  const commandName = loadCommandName(dyldInfo.command);
  const ranges = [
    ["rebase", dyldInfo.rebaseOff, dyldInfo.rebaseSize],
    ["bind", dyldInfo.bindOff, dyldInfo.bindSize],
    ["weak-bind", dyldInfo.weakBindOff, dyldInfo.weakBindSize],
    ["lazy-bind", dyldInfo.lazyBindOff, dyldInfo.lazyBindSize],
    ["export", dyldInfo.exportOff, dyldInfo.exportSize]
  ] as const;
  for (const [label, offset, size] of ranges) {
    if (size <= 0) continue;
    if (!isBigIntRangeWithin(imageSize, BigInt(offset), BigInt(size))) {
      issues.push(
        `Load command ${dyldInfo.loadCommandIndex}: ${commandName} ${label} data range ` +
          `(${offset}, ${size}) extends beyond the Mach-O image.`
      );
    }
  }
};

const validateLinkeditDataRanges = (
  records: MachOLinkeditData[],
  imageSize: number,
  issues: string[]
): void => {
  for (const record of records) {
    if (
      record.datasize > 0 &&
      !isBigIntRangeWithin(imageSize, BigInt(record.dataoff), BigInt(record.datasize))
    ) {
      issues.push(
        `Load command ${record.loadCommandIndex}: ${loadCommandName(record.command)} data range ` +
          `(${record.dataoff}, ${record.datasize}) extends beyond the Mach-O image.`
      );
    }
  }
};

const validateEncryptionInfoRanges = (
  records: MachOEncryptionInfo[],
  imageSize: number,
  issues: string[]
): void => {
  for (const record of records) {
    if (
      record.cryptsize > 0 &&
      !isBigIntRangeWithin(imageSize, BigInt(record.cryptoff), BigInt(record.cryptsize))
    ) {
      issues.push(
        `Load command ${record.loadCommandIndex}: ${loadCommandName(record.command)} encrypted ` +
          `range (${record.cryptoff}, ${record.cryptsize}) extends beyond the Mach-O image.`
      );
    }
  }
};

const validateFileSetEntryRanges = (
  records: MachOFileSetEntry[],
  imageSize: number,
  issues: string[]
): void => {
  const bigLimit = BigInt(imageSize);
  for (const record of records) {
    if (record.fileoff < 0n || record.fileoff >= bigLimit) {
      issues.push(
        `Load command ${record.loadCommandIndex}: fileset entry ${record.entryId || "<unnamed>"} ` +
          `file offset ${record.fileoff} points outside the Mach-O image.`
      );
    }
  }
};

export {
  validateDyldInfoRanges,
  validateEncryptionInfoRanges,
  validateFileSetEntryRanges,
  validateLinkeditDataRanges,
  validateSegmentRanges
};
