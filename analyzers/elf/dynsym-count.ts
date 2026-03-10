"use strict";

import type { ElfProgramHeader } from "./types.js";
import { vaddrToFileOffset } from "./vaddr-to-file-offset.js";

const PT_LOAD = 1;

const toSafeIndex = (value: bigint, label: string, issues: string[]): number | null => {
  const num = Number(value);
  if (!Number.isSafeInteger(num) || num < 0) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};

const findLoadSegmentContainingVaddr = (
  programHeaders: ElfProgramHeader[],
  vaddr: bigint
): ElfProgramHeader | null => {
  for (const ph of programHeaders) {
    if (ph.type !== PT_LOAD || ph.filesz <= 0n) continue;
    const end = ph.vaddr + ph.filesz;
    if (vaddr >= ph.vaddr && vaddr < end) return ph;
  }
  return null;
};

const locateHashTable = (
  programHeaders: ElfProgramHeader[],
  hashVaddr: bigint,
  label: string,
  issues: string[]
): { fileOffset: number; availableBytes: number } | null => {
  const hashOffset = vaddrToFileOffset(programHeaders, hashVaddr);
  if (hashOffset == null) {
    issues.push(`${label} does not map into a PT_LOAD segment.`);
    return null;
  }
  const fileOffset = toSafeIndex(hashOffset, `${label} file offset`, issues);
  if (fileOffset == null) return null;
  const segment = findLoadSegmentContainingVaddr(programHeaders, hashVaddr);
  if (!segment) {
    issues.push(`${label} does not map into a file-backed PT_LOAD segment.`);
    return null;
  }
  const availableBytes = toSafeIndex(segment.offset + segment.filesz - hashOffset, `${label} size`, issues);
  if (availableBytes == null || availableBytes <= 0) return null;
  return { fileOffset, availableBytes };
};

const readSliceView = async (
  file: File,
  offset: number,
  length: number
): Promise<DataView | null> => {
  if (length <= 0 || offset < 0 || offset >= file.size) return null;
  const end = Math.min(file.size, offset + length);
  if (end <= offset) return null;
  const bytes = new Uint8Array(await file.slice(offset, end).arrayBuffer());
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
};

export async function readDynsymCountFromSysvHash(opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  hashVaddr: bigint;
  littleEndian: boolean;
  issues: string[];
}): Promise<number | null> {
  const location = locateHashTable(opts.programHeaders, opts.hashVaddr, "DT_HASH", opts.issues);
  if (!location) return null;
  if (location.availableBytes < 8) {
    opts.issues.push("DT_HASH table header is truncated.");
    return null;
  }
  const header = await readSliceView(opts.file, location.fileOffset, 8);
  if (!header || header.byteLength < 8) {
    opts.issues.push("DT_HASH table header is truncated.");
    return null;
  }
  const nchain = header.getUint32(4, opts.littleEndian);
  return Number.isSafeInteger(nchain) && nchain > 0 ? nchain : null;
}

export async function readDynsymCountFromGnuHash(opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  hashVaddr: bigint;
  is64: boolean;
  littleEndian: boolean;
  issues: string[];
}): Promise<number | null> {
  const location = locateHashTable(opts.programHeaders, opts.hashVaddr, "DT_GNU_HASH", opts.issues);
  if (!location) return null;
  if (location.availableBytes < 16) {
    opts.issues.push("DT_GNU_HASH table header is truncated.");
    return null;
  }

  const header = await readSliceView(opts.file, location.fileOffset, 16);
  if (!header || header.byteLength < 16) {
    opts.issues.push("DT_GNU_HASH table header is truncated.");
    return null;
  }

  const nbuckets = header.getUint32(0, opts.littleEndian);
  const symoffset = header.getUint32(4, opts.littleEndian);
  const bloomSize = header.getUint32(8, opts.littleEndian);
  const pointerSize = opts.is64 ? 8 : 4;
  const bloomBytes = bloomSize * pointerSize;
  const bucketsOffset = 16 + bloomBytes;
  const bucketBytes = nbuckets * 4;
  const chainBase = bucketsOffset + bucketBytes;

  if (!Number.isSafeInteger(bloomBytes) || !Number.isSafeInteger(chainBase)) {
    opts.issues.push("DT_GNU_HASH dimensions are too large to index.");
    return null;
  }
  if (chainBase > location.availableBytes) {
    opts.issues.push("DT_GNU_HASH buckets are truncated.");
    return null;
  }
  if (nbuckets === 0) return symoffset;

  const buckets = await readSliceView(opts.file, location.fileOffset + bucketsOffset, bucketBytes);
  if (!buckets || buckets.byteLength < bucketBytes) {
    opts.issues.push("DT_GNU_HASH buckets are truncated.");
    return null;
  }

  let maxBucket = 0;
  for (let index = 0; index < nbuckets; index += 1) {
    const bucket = buckets.getUint32(index * 4, opts.littleEndian);
    if (bucket > maxBucket) maxBucket = bucket;
  }
  if (maxBucket === 0) return symoffset;
  if (maxBucket < symoffset) {
    opts.issues.push("DT_GNU_HASH bucket value precedes symoffset.");
    return symoffset;
  }

  const chainStartIndex = maxBucket - symoffset;
  const chainOffset = chainBase + chainStartIndex * 4;
  if (!Number.isSafeInteger(chainOffset) || chainOffset >= location.availableBytes) {
    opts.issues.push("DT_GNU_HASH chain table is truncated.");
    return null;
  }

  const chainBytes = location.availableBytes - chainOffset;
  const chains = await readSliceView(opts.file, location.fileOffset + chainOffset, chainBytes);
  if (!chains || chains.byteLength < 4) {
    opts.issues.push("DT_GNU_HASH chain table is truncated.");
    return null;
  }

  const chainCount = Math.floor(chains.byteLength / 4);
  for (let index = 0; index < chainCount; index += 1) {
    const chainValue = chains.getUint32(index * 4, opts.littleEndian);
    if ((chainValue & 1) !== 0) return maxBucket + index + 1;
  }

  opts.issues.push("DT_GNU_HASH chain table is truncated.");
  return null;
}
