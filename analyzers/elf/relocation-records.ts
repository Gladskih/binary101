import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfRelocationImage } from "./relocation-types.js";
import type { ElfRelocation, ElfRelocationTable } from "./relocation-types.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import type { ElfBinaryLayout, ElfSymbolicRelocationRecord } from "./binary-layout-types.js";

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
  if (!(value & 1n)) return { offsets: [value], next: value + BigInt(wordSize) };
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

const supportedTable = (
  layout: ElfBinaryLayout, table: ElfRelocationTable, machine: number
): boolean => table.encoding === "RELR" || layout.supportsSymbolicRelocations(machine);

export async function* readElfRelocationRecords(
  reader: FileRangeReader, table: ElfRelocationTable, elf: ElfRelocationImage,
  tableIndex: number, issues: string[], layout = selectElfBinaryLayout(elf)
): AsyncGenerator<ElfRelocation> {
  let cursor: bigint | null = null;
  const wordSize = layout.wordSize;
  if (!supportedTable(layout, table, elf.header.machine)) {
    issues.push("MIPS64 compound r_info relocation encoding is unsupported.");
    return;
  }
  for (let position = table.offset; position < table.offset + table.size; position += table.entrySize) {
    const view = await reader.read(position, table.entrySize);
    if (view.byteLength < table.entrySize) {
      issues.push("ELF relocation record is truncated.");
      return;
    }
    if (table.encoding !== "RELR") {
      yield symbolicRecord(layout.relocations[table.encoding].read(view)!, tableIndex, position);
      continue;
    }
    const block = decodeRelrBlock(layout.readWord(view)!, cursor, wordSize, issues);
    if (!block) {
      if (cursor != null) return;
      continue;
    }
    for (const offset of block.offsets) yield relativeRecord(offset, tableIndex, position);
    cursor = block.next;
  }
}
