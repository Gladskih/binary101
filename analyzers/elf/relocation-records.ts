import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfRelocationImage } from "./relocation-types.js";
import type { ElfRelocation, ElfRelocationTable } from "./relocation-types.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import type { ElfBinaryLayout, ElfSymbolicRelocationRecord } from "./binary-layout-types.js";
import { ElfRelocationStream } from "./relocation-stream.js";
import { readElfAndroidRelocations } from "./relocation-android.js";
import { readElfCrelRelocations } from "./relocation-crel.js";
import { decodeElfRelocationInfo } from "./relocation-info.js";
import { readElfCompressedRelocations } from "./relocation-compressed.js";

// ELF gABI §6.1 r_info/r_addend and §6.2 RELR bitmap encoding.
// https://gabi.xinuos.com/elf/06-reloc.html
const symbolicRecord = (
  record: ElfSymbolicRelocationRecord,
  tableIndex: number, recordOffset: number
): ElfRelocation => {
  return { tableIndex, recordOffset, ...record, symbol: null, target: null };
};

const relativeRecord = (
  offset: bigint, tableIndex: number, recordOffset: number
): ElfRelocation => ({
  tableIndex, recordOffset, offset, type: null, symbolIndex: null,
  symbol: null, addend: null, target: null
});

const decodeRelrBlock = (
  value: bigint, cursor: bigint | null, wordSize: number, issues: string[]
): { offsets: bigint[]; next: bigint } | null => {
  // gABI RELR: the low bit selects a bitmap; each remaining bit covers one address
  // slot. There are 8 bits per byte, hence 31/63 bitmap slots for ELF32/ELF64.
  if (!(value & 1n)) {
    if (value + BigInt(wordSize) > 1n << BigInt(wordSize * 8)) {
      issues.push("ELF RELR address slot overflows the address space.");
      return null;
    }
    return { offsets: [value], next: value + BigInt(wordSize) };
  }
  if (cursor == null) {
    issues.push("ELF RELR bitmap appears before an address entry.");
    return null;
  }
  const next = cursor + BigInt((wordSize * 8 - 1) * wordSize);
  if (next > (1n << BigInt(wordSize * 8))) {
    issues.push("ELF RELR bitmap overflows the address space.");
    return null;
  }
  const offsets: bigint[] = [];
  for (let bit = 1; bit < wordSize * 8; bit += 1) {
    if (value & (1n << BigInt(bit))) offsets.push(cursor + BigInt((bit - 1) * wordSize));
  }
  return { offsets, next };
};

const packedRecords = async function* (
  reader: FileRangeReader, table: ElfRelocationTable, elf: ElfRelocationImage,
  tableIndex: number, issues: string[]
): AsyncGenerator<ElfRelocation> {
  const stream = new ElfRelocationStream(reader, table.offset, table.size);
  try {
    if (table.encoding === "CREL") yield* readElfCrelRelocations(stream, elf, tableIndex);
    else yield* readElfAndroidRelocations(stream, elf, table.encoding, tableIndex);
    if (table.sources.includes("DT_CREL") && table.sectionIndex == null) {
      table.size = stream.position - table.offset;
    }
    if (stream.position !== stream.end && !table.sources.includes("DT_CREL")) {
      issues.push(`ELF ${table.encoding} has trailing bytes.`);
      return;
    }
    table.complete = true;
  } catch (error) {
    issues.push(`ELF ${table.encoding}: ${error instanceof Error ? error.message : String(error)}.`);
  }
};

const validGeometry = (table: ElfRelocationTable, issues: string[]): boolean => {
  if ([table.offset, table.size, table.entrySize, table.offset + table.size].every(Number.isSafeInteger) &&
    table.offset >= 0 && table.size >= 0 && table.entrySize > 0) return true;
  issues.push("ELF relocation table has an invalid range or entry size.");
  return false;
};

const validStride = (table: ElfRelocationTable, layout: ElfBinaryLayout, issues: string[]): boolean => {
  const stride = table.encoding === "REL" || table.encoding === "RELA" ?
    layout.relocations[table.encoding].entrySize : layout.wordSize;
  if (table.entrySize === stride && table.size % stride === 0) return true;
  issues.push("ELF relocation table has an invalid entry size or partial record.");
  return false;
};

const readSymbolicRecord = (view: DataView, encoding: "REL" | "RELA",
  layout: ElfBinaryLayout, elf: ElfRelocationImage): ElfSymbolicRelocationRecord => {
  const record = layout.relocations[encoding].read(view)!;
  // Only N64 little-endian reinterprets r_info; don't decode generic bytes twice.
  return elf.is64 && elf.header.machine === 8 && elf.littleEndian ?
    { ...record, ...decodeElfRelocationInfo(
      BigInt(record.symbolIndex) << 32n | BigInt(record.type), elf) } : record;
};

const unbasedBitmap = (value: bigint, cursor: bigint | null): boolean =>
  cursor == null && (value & 1n) !== 0n;

async function* readFixedRelocations(
  reader: FileRangeReader, table: ElfRelocationTable, elf: ElfRelocationImage,
  tableIndex: number, issues: string[], layout: ElfBinaryLayout
): AsyncGenerator<ElfRelocation> {
  let cursor: bigint | null = null;
  let complete = true;
  if (!validStride(table, layout, issues)) return;
  for (let position = table.offset; position < table.offset + table.size; position += table.entrySize) {
    const view = await reader.read(position, table.entrySize);
    if (view.byteLength < table.entrySize) {
      issues.push("ELF relocation record is truncated.");
      return;
    }
    if (table.encoding === "REL" || table.encoding === "RELA") {
      yield symbolicRecord(readSymbolicRecord(view, table.encoding, layout, elf), tableIndex, position);
      continue;
    }
    const value = layout.readWord(view)!;
    const block = decodeRelrBlock(value, cursor, layout.wordSize, issues);
    if (!block) {
      complete = false;
      if (!unbasedBitmap(value, cursor)) return;
      continue;
    }
    for (const offset of block.offsets) yield relativeRecord(offset, tableIndex, position);
    cursor = block.next;
  }
  table.complete = complete;
}

export async function* readElfRelocationRecords(
  reader: FileRangeReader, table: ElfRelocationTable, elf: ElfRelocationImage,
  tableIndex: number, issues: string[], layout = selectElfBinaryLayout(elf)
): AsyncGenerator<ElfRelocation> {
  table.complete = false;
  if (!validGeometry(table, issues)) return;
  if (table.compressed) yield* readElfCompressedRelocations(reader, table, elf, tableIndex, issues);
  else if (["REL", "RELA", "RELR", "AUTH_RELR"].includes(table.encoding)) {
    yield* readFixedRelocations(reader, table, elf, tableIndex, issues, layout);
  } else yield* packedRecords(reader, table, elf, tableIndex, issues);
}
