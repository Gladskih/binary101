import type { ElfRelocationImage } from "./relocation-types.js";
import type { ElfRelocationTable, ElfRelocationTarget } from "./relocation-types.js";
import type { ElfSectionHeader } from "./types.js";
import { elfFileRange, elfVirtualRange } from "./relocation-reader.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { ELF_FILE_TYPE, ELF_SECTION_TYPE, ELF_SECTION_FLAG, ELF_SEGMENT_TYPE } from "./abi-constants.js";

// gABI §6: ET_REL r_offset is section-relative; ET_EXEC/ET_DYN use virtual addresses.
// SHT_NOBITS has memory storage but no file bytes.
// https://gabi.xinuos.com/elf/06-reloc.html
const sectionTarget = (
  elf: ElfRelocationImage, table: ElfRelocationTable, offset: bigint, width: bigint, issues: string[],
  logicalSizes: Map<number, bigint>
): ElfRelocationTarget | null => {
  const section = elf.sections.find(item => item.index === table.targetSectionIndex);
  if (section && compressedSection(section)) {
    return compressedTarget(section.index, offset, width, logicalSizes, issues);
  }
  if (!section || offset < 0n || offset + width > section.size) {
    issues.push(`Relocation target ${offset} is outside its target section.`);
    return null;
  }
  return fileBackedTarget(section, offset, width, elf.fileSize, issues);
};

const compressedSection = (section: ElfSectionHeader): boolean =>
  (section.flags & 0x800n) !== 0n || (section.name ?? "").startsWith(".zdebug_");

const fileBackedTarget = (section: ElfSectionHeader, offset: bigint, width: bigint,
  fileSize: number, issues: string[]): ElfRelocationTarget => {
  const range = section.type === ELF_SECTION_TYPE.NOBITS ? null :
    elfFileRange(section.offset + offset, width, fileSize);
  if (section.type !== ELF_SECTION_TYPE.NOBITS && !range) issues.push("Relocation target is outside the file.");
  return { sectionIndex: section.index, sectionOffset: offset,
    fileOffset: range ? BigInt(range.offset) : null };
};

// ELF gABI 3.7: compressed targets use offsets and bounds of the decoded data.
// https://gabi.xinuos.com/elf/03-sheader.html#compressed-sections
const compressedTarget = (sectionIndex: number, offset: bigint, width: bigint,
  logicalSizes: Map<number, bigint>, issues: string[]): ElfRelocationTarget | null => {
  const size = logicalSizes.get(sectionIndex);
  if (size == null) { issues.push("Compressed relocation target requires decoded section bounds."); return null; }
  if (offset < 0n || offset + width > size) {
    issues.push("Relocation target is outside its decoded compressed section.");
    return null;
  }
  return { sectionIndex, sectionOffset: offset, fileOffset: null };
};

const virtualTarget = (
  elf: ElfRelocationImage, offset: bigint, width: bigint, issues: string[]
): ElfRelocationTarget | null => {
  const section = elf.sections.find(item => (item.flags & ELF_SECTION_FLAG.ALLOC) !== 0n &&
    offset >= item.addr && offset + width <= item.addr + item.size);
  const range = elfVirtualRange(elf.programHeaders, offset, width, elf.fileSize);
  const memory = elf.programHeaders.some(item => item.type === ELF_SEGMENT_TYPE.LOAD &&
    offset >= item.vaddr && offset + width <= item.vaddr + item.memsz);
  if (!range && !memory) {
    issues.push(`Relocation target 0x${offset.toString(16)} is outside PT_LOAD memory.`);
    return null;
  }
  return { sectionIndex: section?.index ?? null,
    sectionOffset: section ? offset - section.addr : null,
    fileOffset: range ? BigInt(range.offset) : null };
};

export const locateElfRelocationTarget = (
  elf: ElfRelocationImage, table: ElfRelocationTable, offset: bigint, issues: string[],
  layout = selectElfBinaryLayout(elf), logicalSizes = new Map<number, bigint>()
): ElfRelocationTarget | null => {
  // RELR fixes a whole address-sized slot. Unknown symbolic types only identify a site;
  // their write width belongs to the processor-specific relocation evaluator.
  const width = table.encoding === "RELR" ? BigInt(layout.wordSize) : 1n;
  return elf.header.type === ELF_FILE_TYPE.REL ? sectionTarget(elf, table, offset, width, issues, logicalSizes) :
    virtualTarget(elf, offset, width, issues);
};
