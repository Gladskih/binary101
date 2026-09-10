import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfHashSource, ElfHashTable } from "./hash-types.js";
import type { ElfBinaryLayout } from "./binary-layout-types.js";
import { validateElfHashTable } from "./hash-validation.js";

// Both hash headers use Elf32_Word even in ELF64. GNU Bloom words use the ELF address size.
// https://raw.githubusercontent.com/bminor/glibc/master/elf/dl-lookup.c
const readWords = async (
  reader: FileRangeReader, offset: number, count: number, width: number, layout: ElfBinaryLayout
): Promise<bigint[]> => {
  const words: bigint[] = [];
  for (let index = 0; index < count; index += 1) {
    const view = await reader.read(offset + index * width, width);
    if (view.byteLength !== width) break;
    words.push(width === 8 ? view.getBigUint64(0, layout.byteOrder === "little") :
      BigInt(view.getUint32(0, layout.byteOrder === "little")));
  }
  return words;
};

const readGnuChains = async (
  reader: FileRangeReader, source: ElfHashSource, table: Extract<ElfHashTable, { kind: "gnu" }>,
  chainOffset: number, layout: ElfBinaryLayout
): Promise<void> => {
  const maximumBucket = table.buckets.reduce((maximum, bucket) => Math.max(maximum, bucket), 0);
  if (!maximumBucket) return;
  const available = Math.min(Math.floor((source.size - chainOffset) / 4), 1000000);
  for (let index = 0; index < available; index += 1) {
    const view = await reader.read(source.offset + chainOffset + index * 4, 4);
    if (view.byteLength < 4) break;
    const value = view.getUint32(0, layout.byteOrder === "little");
    table.chains.push(value);
    if (index >= maximumBucket - table.symbolOffset && (value & 1)) return;
  }
  table.issues.push("GNU hash chain is unterminated, truncated or exceeds the entry limit.");
};

export const readElfHashTable = async (
  reader: FileRangeReader, source: ElfHashSource, layout: ElfBinaryLayout
): Promise<ElfHashTable> => {
  const table: ElfHashTable = source.kind === "sysv"
    ? { kind: "sysv", offset: source.offset, buckets: [], chains: [], issues: [] }
    : { kind: "gnu", offset: source.offset, buckets: [], chains: [], issues: [],
      symbolOffset: 0, bloomShift: 0, bloom: [] };
  const headerSize = source.kind === "sysv" ? 8 : 16;
  if (source.size < headerSize) {
    table.issues.push("Hash table header is truncated or outside the file.");
    return table;
  }
  const header = await readWords(reader, source.offset, headerSize / 4, 4, layout);
  if (header.length !== headerSize / 4) {
    table.issues.push("Hash table header is truncated.");
    return table;
  }
  const bucketCount = Number(header[0]);
  const extraCount = Number(header[table.kind === "gnu" ? 2 : 1]);
  const extraWidth = table.kind === "gnu" ? layout.wordSize : 4;
  if (!validDimensions(bucketCount, extraCount, headerSize + bucketCount * 4 + extraCount * extraWidth, source.size)) {
    table.issues.push("Hash table dimensions exceed the file range or the 1000000 entry limit.");
    return table;
  }
  await readHashArrays(reader, source, table, header, layout);
  if (!completeArrays(table, bucketCount, extraCount)) {
    table.issues.push("Hash table arrays are truncated.");
  }
  validateElfHashTable(table);
  return table;
};

const completeArrays = (table: ElfHashTable, buckets: number, extra: number): boolean =>
  table.buckets.length === buckets &&
  (table.kind === "gnu" ? table.bloom.length : table.chains.length) === extra;

const validDimensions = (buckets: number, extra: number, size: number, available: number): boolean =>
  buckets <= 1000000 && extra <= 1000000 && size <= available;

const readHashArrays = async (
  reader: FileRangeReader, source: ElfHashSource, table: ElfHashTable,
  header: bigint[], layout: ElfBinaryLayout
): Promise<void> => {
  if (table.kind === "sysv") {
    table.buckets = (await readWords(reader, source.offset + 8, Number(header[0]), 4, layout)).map(Number);
    table.chains = (await readWords(reader, source.offset + 8 + Number(header[0]) * 4,
      Number(header[1]), 4, layout)).map(Number);
    return;
  }
  table.symbolOffset = Number(header[1]);
  table.bloomShift = Number(header[3]);
  table.bloom = await readWords(reader, source.offset + 16, Number(header[2]), layout.wordSize, layout);
  const bucketOffset = 16 + Number(header[2]) * layout.wordSize;
  table.buckets = (await readWords(reader, source.offset + bucketOffset, Number(header[0]), 4, layout)).map(Number);
  await readGnuChains(reader, source, table, bucketOffset + Number(header[0]) * 4, layout);
};
