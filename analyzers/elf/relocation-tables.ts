import type { ElfRelocationImage } from "./relocation-types.js";
import type { ElfRelocationEncoding, ElfRelocationTable } from "./relocation-types.js";
import { elfVirtualRange } from "./relocation-reader.js";
import type { ElfSectionHeader } from "./types.js";
import type { ElfBinaryLayout } from "./binary-layout-types.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { ELF_DYNAMIC_TAG as DT, ELF_SECTION_TYPE } from "./abi-constants.js";

// gABI sections/dynamic: SHT_RELA=4, SHT_REL=9, SHT_RELR=19;
// DT_RELA=7/8/9, DT_REL=17/18/19, DT_RELR=36/35/37, DT_JMPREL=23.
// https://gabi.xinuos.com/elf/03-sheader.html
// https://gabi.xinuos.com/elf/08-dynamic.html
const entrySize = (encoding: ElfRelocationEncoding, layout: ElfBinaryLayout): number =>
  encoding === "RELR" ? layout.wordSize : layout.relocations[encoding].entrySize;

const sectionByteSize = (
  section: ElfSectionHeader, fileSize: number, stride: number, source: string, issues: string[]
): number | null => {
  if (section.entsize !== BigInt(stride) || section.offset < 0n || section.size < 0n ||
    section.offset > BigInt(fileSize)) {
    issues.push(`ELF relocation ${source} has an invalid range or entry size.`);
    return null;
  }
  const available = BigInt(fileSize) - section.offset;
  const size = Number(section.size > available ? available : section.size);
  if (section.size > available || size % stride) {
    issues.push(`ELF relocation ${source} is truncated or has a partial entry.`);
  }
  return size - size % stride;
};

const sectionTables = (
  elf: ElfRelocationImage, issues: string[], layout: ElfBinaryLayout
): ElfRelocationTable[] =>
  elf.sections.flatMap(section => {
    const encoding = ({ [ELF_SECTION_TYPE.RELA]: "RELA", [ELF_SECTION_TYPE.REL]: "REL",
      [ELF_SECTION_TYPE.RELR]: "RELR" } as const)[section.type];
    if (!encoding || section.size === 0n) return [];
    const source = section.name || `section #${section.index}`;
    const stride = entrySize(encoding, layout);
    const size = sectionByteSize(section, elf.fileSize, stride, source, issues);
    if (size == null) return [];
    return [{ offset: Number(section.offset), size, entrySize: stride,
      encoding, sources: [source], sectionIndex: section.index,
      symbolTableIndex: encoding === "RELR" ? null : section.link,
      targetSectionIndex: section.info || null }];
  });

const validateRelativePrefix = (
  tags: Map<number, bigint>, source: string, count: number, issues: string[]
): void => {
  // DT_RELCOUNT/DT_RELACOUNT describe a prefix, not an additional relocation table.
  // https://raw.githubusercontent.com/bminor/glibc/master/elf/elf.h
  if (source !== "DT_REL" && source !== "DT_RELA") return;
  const relativeCount = tags.get(source === "DT_REL" ? DT.RELCOUNT : DT.RELACOUNT);
  if (relativeCount != null && (relativeCount < 0n || relativeCount > BigInt(count))) {
    issues.push(`ELF ${source} relative prefix count exceeds its relocation table.`);
  }
};

const dynamicRange = (
  elf: ElfRelocationImage, tags: Map<number, bigint>, tagIds: [number, number, number]
): { offset: number; size: number } | null => {
  const address = tags.get(tagIds[0]);
  const size = tags.get(tagIds[1]);
  return address == null || size == null ? null :
    elfVirtualRange(elf.programHeaders, address, size, elf.fileSize);
};

const dynamicTable = (
  elf: ElfRelocationImage, tags: Map<number, bigint>, encoding: ElfRelocationEncoding,
  source: string, tagIds: [number, number, number], issues: string[], layout: ElfBinaryLayout
): ElfRelocationTable | null => {
  const [addressId, sizeId, entryId] = tagIds;
  if (!tags.has(addressId) && !tags.has(sizeId)) return null;
  const stride = entrySize(encoding, layout);
  // DT_PLTREL identifies REL/RELA; PLT records have the corresponding ABI size.
  const declaredStride = source === "DT_JMPREL" ? BigInt(stride) : tags.get(entryId);
  const range = dynamicRange(elf, tags, tagIds);
  if (!range || declaredStride !== BigInt(stride)) {
    issues.push(`ELF ${source} relocation table has invalid tags, size or PT_LOAD mapping.`);
    return null;
  }
  if (range.size % stride) issues.push(`ELF ${source} relocation table has a partial entry.`);
  validateRelativePrefix(tags, source, Math.floor(range.size / stride), issues);
  return { offset: range.offset, size: range.size - range.size % stride, entrySize: stride,
    encoding, sources: [source], sectionIndex: null, symbolTableIndex: null,
    targetSectionIndex: null };
};

const pltTable = (
  elf: ElfRelocationImage, tags: Map<number, bigint>, issues: string[], layout: ElfBinaryLayout
): ElfRelocationTable | null => {
  if (!tags.has(DT.JMPREL) && !tags.has(DT.PLTRELSZ)) return null;
  const encoding = tags.get(DT.PLTREL) === BigInt(DT.RELA) ? "RELA" :
    tags.get(DT.PLTREL) === BigInt(DT.REL) ? "REL" : null;
  if (encoding) return dynamicTable(elf, tags, encoding, "DT_JMPREL",
    [DT.JMPREL, DT.PLTRELSZ, DT.PLTREL], issues, layout);
  issues.push("ELF DT_JMPREL requires DT_PLTREL equal to DT_REL or DT_RELA.");
  return null;
};

export const collectElfRelocationTables = (
  elf: ElfRelocationImage, tags: Map<number, bigint>, issues: string[],
  layout = selectElfBinaryLayout(elf)
): ElfRelocationTable[] => {
  const tables = sectionTables(elf, issues, layout);
  const dynamic = [
    dynamicTable(elf, tags, "REL", "DT_REL", [DT.REL, DT.RELSZ, DT.RELENT], issues, layout),
    dynamicTable(elf, tags, "RELA", "DT_RELA", [DT.RELA, DT.RELASZ, DT.RELAENT], issues, layout),
    dynamicTable(elf, tags, "RELR", "DT_RELR", [DT.RELR, DT.RELRSZ, DT.RELRENT], issues, layout),
    pltTable(elf, tags, issues, layout)
  ];
  for (const table of dynamic) {
    if (!table || !table.size) continue;
    const existing = tables.find(item => item.offset === table.offset && item.size === table.size &&
      item.encoding === table.encoding);
    if (existing) existing.sources.push(...table.sources);
    else tables.push(table);
  }
  return tables;
};
