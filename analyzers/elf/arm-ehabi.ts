import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import { DwarfCursor } from "../dwarf/cursor.js";
import type { ElfParseResult } from "./types.js";
import type { ArmEhabiEntry, ArmEhabiTable } from "./arm-ehabi-types.js";
import { elfFileRange } from "./relocation-reader.js";
import { armPrel31, readArmEhabiProgram } from "./arm-ehabi-program.js";
import { readArmEhabiDescriptors } from "./arm-ehabi-descriptors.js";

// Arm ELF ABI: SHT_ARM_EXIDX / PT_ARM_EXIDX. EHABI32: each index entry is two words.
const exidxSources = (elf: ElfParseResult) => {
  const sections = elf.sections.filter(section => section.type === 0x70000001)
    .map(section => ({ source: `Section #${section.index}`, offset: section.offset,
      size: section.size, address: section.addr, compressed: (section.flags & 0x800n) !== 0n }));
  return sections.length ? sections : elf.programHeaders.filter(header => header.type === 0x70000001)
    .map(header => ({ source: `Segment #${header.index}`, offset: header.offset,
      size: header.filesz, address: header.vaddr, compressed: false }));
};

const extabRange = (elf: ElfParseResult, address: bigint) => {
  const section = elf.sections.find(item => item.name === ".ARM.extab" &&
    address >= item.addr && address < item.addr + item.size);
  if (section && (section.flags & 0x800n)) return null;
  if (section) return { offset: section.offset + address - section.addr,
    size: section.addr + section.size - address };
  const segment = elf.programHeaders.find(item => item.type === 1 &&
    address >= item.vaddr && address < item.vaddr + item.filesz);
  return segment ? { offset: segment.offset + address - segment.vaddr,
    size: segment.vaddr + segment.filesz - address } : null;
};

const readExtab = async (reader: FileRangeReader, elf: ElfParseResult,
  entry: ArmEhabiEntry, nextAddress?: bigint): Promise<void> => {
  const mapped = extabRange(elf, entry.tableAddress!);
  if (mapped && nextAddress != null && nextAddress - entry.tableAddress! < mapped.size) {
    mapped.size = nextAddress - entry.tableAddress!;
  }
  const range = mapped && elfFileRange(mapped.offset, mapped.size, reader.size);
  if (!range || entry.tableAddress! % 4n) {
    entry.issues.push("EHABI extab pointer is unaligned, truncated or outside file-backed data.");
    return;
  }
  const cursor = new DwarfCursor(reader, { ...range, name: "EHABI extab", compressed: false },
    0, range.size, elf.littleEndian, entry.issues);
  await readExtabContents(cursor, entry);
};

const readExtabContents = async (cursor: DwarfCursor, entry: ArmEhabiEntry): Promise<void> => {
  const word = await cursor.uint32();
  if (word != null) await readArmEhabiProgram(word, cursor, entry);
  if (typeof entry.personality === "number" && !entry.issues.length) {
    entry.descriptors = await readArmEhabiDescriptors(cursor, entry.personality, entry.tableAddress!);
  }
};

const readEntry = async (reader: FileRangeReader, elf: ElfParseResult,
  offset: number, address: bigint): Promise<ArmEhabiEntry> => {
  const view = await reader.read(offset, 8);
  const entry: ArmEhabiEntry = { offset, functionAddress: null, data: 0, instructions: [], issues: [] };
  if (view.byteLength < 8) { entry.issues.push("Truncated EHABI index entry."); return entry; }
  const functionWord = view.getUint32(0, elf.littleEndian);
  entry.data = view.getUint32(4, elf.littleEndian);
  if (elf.header.type === 1) entry.issues.push("EHABI addresses require relocations in this relocatable object.");
  else entry.functionAddress = armPrel31(functionWord, address);
  if (functionWord & 0x80000000) entry.issues.push("Reserved high bit in EHABI function PREL31.");
  if (entry.data === 1) entry.instructions.push({ offset: 0, text: "cannot unwind" });
  else if (entry.data & 0x80000000) await readArmEhabiProgram(entry.data, null, entry);
  else if (elf.header.type !== 1) {
    entry.tableAddress = armPrel31(entry.data, address + 4n);
  }
  return entry;
};

const readTable = async (reader: FileRangeReader, elf: ElfParseResult,
  source: ReturnType<typeof exidxSources>[number]): Promise<ArmEhabiTable> => {
  const table: ArmEhabiTable = { source: source.source, entries: [], issues: [] };
  const range = elfFileRange(source.offset, source.size, reader.size);
  if (!range || source.compressed) {
    table.issues.push("EHABI index is compressed, truncated or outside the file.");
    return table;
  }
  if (range.size % 8) table.issues.push("EHABI index size is not a multiple of 8.");
  const count = Math.min(Math.floor(range.size / 8), 100000); // Bound hostile table expansion.
  if (range.size / 8 > 100000) table.issues.push("EHABI index entry limit reached.");
  let previous: bigint | null = null;
  for (let index = 0; index < count; index++) {
    const entry = await readEntry(reader, elf, range.offset + index * 8, source.address + BigInt(index * 8));
    if (previous != null && entry.functionAddress != null && entry.functionAddress <= previous) {
      table.issues.push("EHABI function addresses are not in strictly increasing order.");
    }
    previous = entry.functionAddress;
    table.entries.push(entry);
  }
  return table;
};

const resolveExtabs = async (reader: FileRangeReader, elf: ElfParseResult,
  tables: ArmEhabiTable[]): Promise<void> => {
  const groups = new Map<bigint, ArmEhabiEntry[]>();
  for (const entry of tables.flatMap(table => table.entries)) {
    if (entry.tableAddress == null) continue;
    const group = groups.get(entry.tableAddress) ?? [];
    group.push(entry);
    groups.set(entry.tableAddress, group);
  }
  const addresses = [...groups.keys()].sort((left, right) => left < right ? -1 : 1);
  for (const [index, address] of addresses.entries()) {
    const [first, ...others] = groups.get(address)!;
    const decoded: ArmEhabiEntry = { ...first!, issues: [] };
    await readExtab(reader, elf, decoded, addresses[index + 1]);
    for (const entry of [first!, ...others]) {
      if (decoded.personality != null) entry.personality = decoded.personality;
      entry.instructions = decoded.instructions;
      if (decoded.descriptors) entry.descriptors = decoded.descriptors;
      entry.issues.push(...decoded.issues);
    }
  }
};

export const parseElfArmEhabi = async (file: File, elf: ElfParseResult): Promise<ArmEhabiTable[]> => {
  if (elf.header.machine !== 40 || elf.is64) return [];
  const reader = createFileRangeReader(file, 0, file.size);
  const tables: ArmEhabiTable[] = [];
  for (const source of exidxSources(elf)) tables.push(await readTable(reader, elf, source));
  await resolveExtabs(reader, elf, tables);
  return tables;
};
