"use strict";

import { createRangeReader, isRangeWithin } from "./format.js";
import type { MachOMagicInfo } from "./format.js";
import type { MachOFatHeader, MachOFatSlice, MachOImage, MachOParseResult } from "./types.js";
import { parseThinImage } from "./thin.js";

const sliceDataStartsBeforeRecords = (
  sliceOffset: number,
  parsedSliceRecords: number,
  headerSize: number,
  archSize: number
): boolean => sliceOffset < headerSize + parsedSliceRecords * archSize;

const sliceOffsetMisaligned = (sliceOffset: number, align: number): boolean => {
  if (align === 0) return false;
  const sliceOffsetBigInt = BigInt(sliceOffset);
  if (align >= 63) return sliceOffsetBigInt !== 0n;
  return sliceOffsetBigInt % (1n << BigInt(align)) !== 0n;
};

const parseFatBinary = async (
  file: File,
  magicInfo: MachOMagicInfo
): Promise<MachOParseResult> => {
  const issues: string[] = [];
  const headerSize = 8;
  // fat_header + fat_arch / fat_arch_64 from mach-o/fat.h.
  const archSize = magicInfo.is64 ? 32 : 20;
  const reader = createRangeReader(file, 0, file.size);
  const headerView = await reader.read(0, headerSize);
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
  const availableSlices = Math.floor(Math.max(0, file.size - headerSize) / archSize);
  const parsedSliceRecords = Math.min(nfatArch, availableSlices);
  if (availableSlices < nfatArch) {
    issues.push(`Fat binary declares ${nfatArch} slices but only ${availableSlices} architecture records fit in the file.`);
  }
  const slices: MachOFatSlice[] = [];
  for (let index = 0; index < parsedSliceRecords; index += 1) {
    const offset = headerSize + index * archSize;
    const sliceView = await reader.read(offset, archSize);
    const cputype = sliceView.getUint32(0, little);
    const cpusubtype = sliceView.getUint32(4, little);
    const sliceOffset = magicInfo.is64
      ? Number(sliceView.getBigUint64(8, little))
      : sliceView.getUint32(8, little);
    const size = magicInfo.is64
      ? Number(sliceView.getBigUint64(16, little))
      : sliceView.getUint32(12, little);
    const align = sliceView.getUint32(magicInfo.is64 ? 24 : 16, little);
    const reserved = magicInfo.is64 ? sliceView.getUint32(28, little) : null;
    const sliceIssues: string[] = [];
    let image: MachOImage | null = null;
    if (sliceDataStartsBeforeRecords(sliceOffset, parsedSliceRecords, headerSize, archSize)) {
      sliceIssues.push(
        `Slice ${index} offset ${sliceOffset} overlaps the fat architecture table ending at ${headerSize + parsedSliceRecords * archSize}.`
      );
    }
    if (sliceOffsetMisaligned(sliceOffset, align)) {
      sliceIssues.push(`Slice ${index} offset ${sliceOffset} is not aligned to 2^${align} bytes.`);
    }
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
  const slicesByOffset = [...slices].sort((left, right) => left.offset - right.offset || left.index - right.index);
  for (let index = 1; index < slicesByOffset.length; index += 1) {
    const previous = slicesByOffset[index - 1];
    const current = slicesByOffset[index];
    if (!previous || !current) continue;
    if (previous.offset + previous.size <= current.offset) continue;
    current.issues.push(
      `Slice ${current.index} range (${current.offset}, ${current.size}) overlaps slice ${previous.index} range (${previous.offset}, ${previous.size}).`
    );
  }
  return { kind: "fat", fileSize: file.size, image: null, fatHeader, slices, issues };
};

export { parseFatBinary };
