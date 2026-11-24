import { createFileRangeReader, DEFAULT_FILE_READ_WINDOW_BYTES, type FileRangeReader } from "../file-range-reader.js";
import type { ElfProgramHeader } from "./types.js";
import { elfVirtualExtent } from "./relocation-reader.js";

const locateHashTable = (
  file: File, programHeaders: ElfProgramHeader[],
  hashVaddr: bigint,
  label: string,
  issues: string[]
): { offset: number; size: number } | null => {
  const range = elfVirtualExtent(programHeaders, hashVaddr, file.size);
  if (!range) issues.push(`${label} does not map into file-backed PT_LOAD data.`);
  return range;
};

async function* hashWords(
  reader: FileRangeReader, offset: number, count: number, littleEndian: boolean
): AsyncGenerator<number> {
  const size = count * 4;
  for (let position = 0; position < size;) {
    const length = Math.min(size - position, DEFAULT_FILE_READ_WINDOW_BYTES);
    const view = await reader.read(offset + position, length);
    if (view.byteLength !== length) return;
    for (let index = 0; index < length; index += 4) yield view.getUint32(index, littleEndian);
    position += length;
  }
}

export async function readDynsymCountFromSysvHash(opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  hashVaddr: bigint;
  littleEndian: boolean;
  issues: string[];
}): Promise<number | null> {
  const location = locateHashTable(opts.file, opts.programHeaders, opts.hashVaddr, "DT_HASH", opts.issues);
  if (!location) return null;
  if (location.size < 8) {
    opts.issues.push("DT_HASH table header is truncated.");
    return null;
  }
  const header = await createFileRangeReader(opts.file, location.offset, location.size).read(0, 8);
  if (header.byteLength < 8) {
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
  const location = locateHashTable(opts.file, opts.programHeaders, opts.hashVaddr, "DT_GNU_HASH", opts.issues);
  if (!location) return null;
  if (location.size < 16) {
    opts.issues.push("DT_GNU_HASH table header is truncated.");
    return null;
  }

  const reader = createFileRangeReader(opts.file, location.offset, location.size);
  const header = await reader.read(0, 16);
  if (header.byteLength < 16) {
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
  if (chainBase > location.size) {
    opts.issues.push("DT_GNU_HASH buckets are truncated.");
    return null;
  }
  if (nbuckets === 0) return null;

  let maxBucket = 0;
  let observedBuckets = 0;
  for await (const bucket of hashWords(reader, bucketsOffset, nbuckets, opts.littleEndian)) {
    maxBucket = Math.max(maxBucket, bucket);
    observedBuckets += 1;
  }
  if (observedBuckets !== nbuckets) {
    opts.issues.push("DT_GNU_HASH buckets are truncated.");
    return null;
  }
  // GNU ld records symoffset=1 even when the table contains no hashed symbols.
  // https://gnu.googlesource.com/binutils-gdb/+/4d9e2e53b9f93b0ae33ba948ae3d2825b3424441/bfd/elflink.c#7563
  if (maxBucket === 0) return null;
  if (maxBucket < symoffset) {
    opts.issues.push("DT_GNU_HASH bucket value precedes symoffset.");
    return null;
  }

  const chainStartIndex = maxBucket - symoffset;
  const chainOffset = chainBase + chainStartIndex * 4;
  if (!Number.isSafeInteger(chainOffset) || chainOffset >= location.size) {
    opts.issues.push("DT_GNU_HASH chain table is truncated.");
    return null;
  }

  let count = maxBucket;
  const chainCount = Math.floor((location.size - chainOffset) / 4);
  for await (const chainValue of hashWords(reader, chainOffset, chainCount, opts.littleEndian)) {
    count += 1;
    if ((chainValue & 1) !== 0) return count;
  }

  opts.issues.push("DT_GNU_HASH chain table is truncated.");
  return null;
}
