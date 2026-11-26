import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import { ELF_FILE_TYPE, ELF_SECTION_FLAG, ELF_SECTION_TYPE, ELF_SEGMENT_TYPE } from "./abi-constants.js";
import { elfFileRange } from "./relocation-reader.js";
import { readSFrameDescriptor, readSFrameHeader, SFRAME_DESCRIPTOR_SIZES, SFRAME_HEADER_SIZE } from
  "./sframe-layout.js";
import { readSFrameRows } from "./sframe-rows.js";
import type { ElfSFrame } from "./sframe-types.js";
import type { ElfParseResult } from "./types.js";

const sframeSources = (elf: ElfParseResult) => {
  const sections = elf.sections.filter(section => section.type === ELF_SECTION_TYPE.GNU_SFRAME ||
    (section.type === ELF_SECTION_TYPE.PROGBITS && section.name === ".sframe"));
  const segments = elf.programHeaders.filter(segment => segment.type === ELF_SEGMENT_TYPE.GNU_SFRAME);
  const sources = [
    ...sections.map(section => ({
      source: { sectionIndex: section.index }, offset: section.offset, size: section.size,
      address: section.addr, flags: section.flags
    })),
    ...segments.map(segment => ({
      source: { programHeaderIndex: segment.index }, offset: segment.offset, size: segment.filesz,
      address: segment.vaddr, flags: 0n
    }))
  ];
  // Sections precede segments describing the same bytes at the same virtual address.
  const seen = new Set<string>();
  return sources.filter(({ offset, size, address, flags }) => {
    const key = `${offset}:${size}:${address}:${flags & ELF_SECTION_FLAG.COMPRESSED}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

const readBody = async (reader: FileRangeReader, little: boolean, table: ElfSFrame): Promise<void> => {
  const { header, preamble } = table;
  if (!header || !preamble) return;
  const { version } = preamble;
  const base = SFRAME_HEADER_SIZE + header.auxSize;
  const start = base + header.functionOffset;
  const rows = base + header.rowOffset;
  const end = rows + header.rowBytes;
  const entrySize = SFRAME_DESCRIPTOR_SIZES[version]!;
  if (start + header.functionCount * entrySize > rows || end > reader.size) {
    table.issues.push("SFrame descriptor and frame row areas overlap or extend beyond the data.");
    return;
  }
  for (let index = 0; index < header.functionCount; index++) {
    const entry = await readSFrameDescriptor(reader, little, start + index * entrySize, version);
    if (!entry) { table.issues.push("Truncated SFrame function descriptor."); break; }
    table.functions.push(entry);
  }
  await readSFrameRows(reader, little, rows, end, table);
  if (table.rows.length !== header.rowCount) {
    table.issues.push(`SFrame header declares ${header.rowCount} frame rows; decoded ${table.rows.length}.`);
  }
};

const readTable = async (file: File, elf: ElfParseResult,
  source: ReturnType<typeof sframeSources>[number]): Promise<ElfSFrame> => {
  const table: ElfSFrame = { source: source.source,
    address: elf.header.type === ELF_FILE_TYPE.REL ? null : source.address,
    functions: [], rows: [], issues: [] };
  const range = elfFileRange(source.offset, source.size, file.size);
  if (!range || (source.flags & ELF_SECTION_FLAG.COMPRESSED)) {
    table.issues.push("SFrame data is compressed, truncated or outside the file.");
    return table;
  }
  const reader = createFileRangeReader(file, range.offset, range.size);
  await readSFrameHeader(reader, elf.littleEndian, table);
  await readBody(reader, elf.littleEndian, table);
  return table;
};

export const parseElfSFrame = async (file: File, elf: ElfParseResult): Promise<ElfSFrame[]> => {
  const tables: ElfSFrame[] = [];
  for (const source of sframeSources(elf)) tables.push(await readTable(file, elf, source));
  return tables;
};
