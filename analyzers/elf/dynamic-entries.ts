import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfRelocationImage } from "./relocation-types.js";
import { elfFileRange } from "./relocation-reader.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { ELF_DYNAMIC_TAG, ELF_SECTION_TYPE, ELF_SEGMENT_TYPE } from "./abi-constants.js";

export interface ElfDynamicEntry {
  tag: number;
  value: bigint;
}

// gABI §8.3: dynamic entries are class-sized pairs, terminated by DT_NULL.
// https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
const dynamicRange = (
  reader: FileRangeReader,
  elf: Pick<ElfRelocationImage, "programHeaders" | "sections">,
  issues: string[]
): { offset: number; size: number } | null => {
  const segment = elf.programHeaders.find(header => header.type === ELF_SEGMENT_TYPE.DYNAMIC && header.filesz > 0n);
  const section = elf.sections.find(header => header.type === ELF_SECTION_TYPE.DYNAMIC && header.size > 0n);
  const source = segment ? { offset: segment.offset, size: segment.filesz } : section;
  if (!source) return null;
  const range = elfFileRange(source.offset, source.size, reader.size);
  if (!range) {
    issues.push("ELF dynamic table is truncated or outside the file.");
  }
  return range;
};

export const readElfDynamicEntries = async (
  reader: FileRangeReader,
  elf: Pick<ElfRelocationImage, "programHeaders" | "sections" | "is64" | "littleEndian">,
  issues: string[],
  layout = selectElfBinaryLayout(elf)
): Promise<ElfDynamicEntry[]> => {
  const range = dynamicRange(reader, elf, issues);
  if (!range) return [];
  const stride = layout.dynamicEntrySize;
  if (range.size % stride) issues.push("ELF dynamic table has a partial entry.");
  const entries: ElfDynamicEntry[] = [];
  for (let position = range.offset; position + stride <= range.offset + range.size; position += stride) {
    const record = layout.readDynamic(await reader.read(position, stride));
    if (!record) break;
    const tag = Number(record.tag);
    if (tag === ELF_DYNAMIC_TAG.NULL) return entries;
    if (Number.isSafeInteger(tag)) {
      entries.push({ tag, value: record.value });
    }
  }
  issues.push("ELF dynamic table is missing DT_NULL.");
  return entries;
};
