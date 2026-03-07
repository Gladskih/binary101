"use strict";

import { clampRangeSize, isRangeWithin, readRange } from "./format.js";
import type { MachOMagicInfo } from "./format.js";
import type { MachOFatHeader, MachOFatSlice, MachOImage, MachOParseResult } from "./types.js";
import { parseThinImage } from "./thin.js";

const parseFatBinary = async (
  file: File,
  magicInfo: MachOMagicInfo
): Promise<MachOParseResult> => {
  const issues: string[] = [];
  const headerSize = 8;
  // fat_header + fat_arch / fat_arch_64 from mach-o/fat.h.
  const archSize = magicInfo.is64 ? 32 : 20;
  const headerView = await readRange(file, 0, Math.min(file.size, headerSize));
  const little = magicInfo.littleEndian;
  if (headerView.byteLength < headerSize) {
    issues.push("Fat header is truncated.");
    return { kind: "fat", fileSize: file.size, image: null, fatHeader: null, slices: [], issues };
  }
  const nfatArch = headerView.getUint32(4, little);
  const fatHeader: MachOFatHeader = {
    magic: magicInfo.magic,
    is64: magicInfo.is64,
    littleEndian: little,
    nfatArch
  };
  const directoryBytes = clampRangeSize(file.size, 0, headerSize + nfatArch * archSize);
  const directoryView = await readRange(file, 0, directoryBytes);
  const availableSlices = Math.floor(Math.max(0, directoryView.byteLength - headerSize) / archSize);
  if (availableSlices < nfatArch) {
    issues.push(`Fat binary declares ${nfatArch} slices but only ${availableSlices} architecture records fit in the file.`);
  }
  const slices: MachOFatSlice[] = [];
  for (let index = 0; index < Math.min(nfatArch, availableSlices); index += 1) {
    const offset = headerSize + index * archSize;
    const cputype = directoryView.getUint32(offset, little);
    const cpusubtype = directoryView.getUint32(offset + 4, little);
    const sliceOffset = magicInfo.is64
      ? Number(directoryView.getBigUint64(offset + 8, little))
      : directoryView.getUint32(offset + 8, little);
    const size = magicInfo.is64
      ? Number(directoryView.getBigUint64(offset + 16, little))
      : directoryView.getUint32(offset + 12, little);
    const align = directoryView.getUint32(offset + (magicInfo.is64 ? 24 : 16), little);
    const reserved = magicInfo.is64 ? directoryView.getUint32(offset + 28, little) : null;
    const sliceIssues: string[] = [];
    let image: MachOImage | null = null;
    if (!isRangeWithin(file.size, sliceOffset, size)) {
      sliceIssues.push(`Slice ${index} range (${sliceOffset}, ${size}) extends beyond the file.`);
    } else {
      image = await parseThinImage(file, sliceOffset, size);
      if (!image) sliceIssues.push(`Slice ${index} does not contain a supported Mach-O image.`);
    }
    slices.push({
      index,
      cputype,
      cpusubtype,
      offset: sliceOffset,
      size,
      align,
      reserved,
      image,
      issues: sliceIssues
    });
  }
  return { kind: "fat", fileSize: file.size, image: null, fatHeader, slices, issues };
};

export { parseFatBinary };
