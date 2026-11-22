import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfRelocationImage } from "./relocation-types.js";
import { elfFileRange } from "./relocation-reader.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { ELF_DYNAMIC_TAG, ELF_SECTION_TYPE, ELF_SEGMENT_TYPE } from "./abi-constants.js";
import { ELF_SECTION_COMPRESSED, openElfSectionData, type ElfSectionEncoding } from "./section-data.js";
import type { ElfProgramHeader } from "./types.js";

export interface ElfDynamicEntry {
  tag: number | bigint;
  value: bigint;
}

export interface ElfDynamicTable {
  entries: ElfDynamicEntry[];
  terminated: boolean;
}

// gABI §8.3: dynamic entries are class-sized pairs, terminated by DT_NULL.
// https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
type DynamicImage = Pick<ElfRelocationImage, "programHeaders" | "sections"> & ElfSectionEncoding;

export const findElfDynamicSegment = (headers: ElfProgramHeader[]): ElfProgramHeader | undefined =>
  headers.find(header => header.type === ELF_SEGMENT_TYPE.DYNAMIC && header.filesz > 0n);

const dynamicRange = async (
  reader: FileRangeReader,
  elf: DynamicImage,
  issues: string[]
): Promise<{ offset: number; size: number; reader: FileRangeReader } | null> => {
  const segment = findElfDynamicSegment(elf.programHeaders);
  const section = elf.sections.find(header => header.type === ELF_SECTION_TYPE.DYNAMIC && header.size > 0n);
  if (section && (section.flags & ELF_SECTION_COMPRESSED)) {
    if (!segment) return openElfSectionData(reader, section, elf, issues);
    if (section.offset === segment.offset) {
      issues.push("PT_DYNAMIC points into a compressed SHT_DYNAMIC section.");
      return null;
    }
  }
  const source = segment ? { offset: segment.offset, size: segment.filesz } : section;
  if (!source) return null;
  const range = elfFileRange(source.offset, source.size, reader.size);
  if (!range) {
    issues.push("ELF dynamic table is truncated or outside the file.");
  }
  return range && { ...range, reader };
};

export const readElfDynamicTable = async (
  reader: FileRangeReader,
  elf: DynamicImage,
  issues: string[],
  layout = selectElfBinaryLayout(elf)
): Promise<ElfDynamicTable> => {
  const range = await dynamicRange(reader, elf, issues);
  if (!range) return { entries: [], terminated: false };
  const stride = layout.dynamicEntrySize;
  if (range.size % stride) issues.push("ELF dynamic table has a partial entry.");
  const entries: ElfDynamicEntry[] = [];
  for (let position = range.offset; position + stride <= range.offset + range.size; position += stride) {
    const record = layout.readDynamic(await range.reader.read(position, stride));
    if (!record) break;
    const tag = Number(record.tag);
    if (tag === ELF_DYNAMIC_TAG.NULL) return { entries, terminated: true };
    entries.push({ tag: Number.isSafeInteger(tag) ? tag : record.tag, value: record.value });
  }
  issues.push("ELF dynamic table is missing DT_NULL.");
  return { entries, terminated: false };
};

export const readElfDynamicEntries = async (
  reader: FileRangeReader,
  elf: DynamicImage,
  issues: string[], layout = selectElfBinaryLayout(elf)
): Promise<ElfDynamicEntry[]> => (await readElfDynamicTable(reader, elf, issues, layout)).entries;
