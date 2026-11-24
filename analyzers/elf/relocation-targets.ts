import type { ElfRelocationImage } from "./relocation-types.js";
import type { ElfRelocationTable, ElfRelocationTarget } from "./relocation-types.js";
import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { elfFileRange, elfVirtualRange } from "./relocation-reader.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { ELF_FILE_TYPE, ELF_SECTION_TYPE, ELF_SECTION_FLAG, ELF_SEGMENT_TYPE } from "./abi-constants.js";

const sectionTarget = (
  section: ElfSectionHeader | undefined, offset: bigint, width: bigint, fileSize: number,
  issues: string[], logicalSizes: Map<number, bigint>
): ElfRelocationTarget | null => {
  if (section && compressedSection(section)) {
    return compressedTarget(section.index, offset, width, logicalSizes, issues);
  }
  if (!section || offset < 0n || offset + width > section.size) {
    issues.push(`Relocation target ${offset} is outside its target section.`);
    return null;
  }
  return fileBackedTarget(section, offset, width, fileSize, issues);
};

const compressedSection = (section: ElfSectionHeader): boolean =>
  (section.flags & 0x800n) !== 0n || (section.name ?? "").startsWith(".zdebug_");

const allocatedSection = (section: ElfSectionHeader): boolean =>
  (section.flags & ELF_SECTION_FLAG.ALLOC) !== 0n;

// TLS zero-fill is part of the per-thread template and may share an address
// with a different section in PT_LOAD. https://gabi.xinuos.com/elf/07-pheader.html
const tlsZeroFill = (section: ElfSectionHeader): boolean =>
  section.type === ELF_SECTION_TYPE.NOBITS && (section.flags & ELF_SECTION_FLAG.TLS) !== 0n;

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

const coveredByLoads = (loads: ElfProgramHeader[], start: bigint, end: bigint): boolean => {
  if (loads.some(load => load.vaddr <= start && load.vaddr + load.memsz >= end)) return true;
  // A write may cross contiguous mapped segments. Only gaps make memory unavailable.
  loads.sort((left, right) => left.vaddr < right.vaddr ? -1 : left.vaddr > right.vaddr ? 1 : 0);
  let covered = start;
  for (const load of loads) {
    if (load.vaddr > covered) break;
    if (load.vaddr + load.memsz > covered) covered = load.vaddr + load.memsz;
    if (covered >= end) return true;
  }
  return false;
};

const virtualTarget = (
  elf: ElfRelocationImage, offset: bigint, width: bigint, issues: string[]
): ElfRelocationTarget | null => {
  const end = offset + width;
  if (offset < 0n || end > (1n << (elf.is64 ? 64n : 32n))) {
    issues.push("Relocation target range exceeds the ELF address space.");
    return null;
  }
  const loads = elf.programHeaders.filter(load => load.type === ELF_SEGMENT_TYPE.LOAD &&
    load.memsz > 0n && load.vaddr < end && load.vaddr + load.memsz > offset);
  if (!coveredByLoads(loads, offset, end)) {
    issues.push(width === 1n ? "Relocation target address is outside PT_LOAD memory." :
      `Relocation target range (${width}-byte write) is outside PT_LOAD memory.`);
    return null;
  }
  const section = elf.sections.find(item => allocatedSection(item) && !tlsZeroFill(item) &&
    offset >= item.addr && end <= item.addr + item.size);
  const range = elfVirtualRange(loads, offset, width, elf.fileSize);
  return { sectionIndex: section?.index ?? null,
    sectionOffset: section ? offset - section.addr : null,
    fileOffset: range ? BigInt(range.offset) : null };
};

export const locateElfRelocationTarget = (
  elf: ElfRelocationImage, table: ElfRelocationTable, offset: bigint, issues: string[],
  layout = selectElfBinaryLayout(elf), logicalSizes = new Map<number, bigint>(), writeSize?: bigint
): ElfRelocationTarget | null => {
  // RELR fixes a whole address-sized slot. Unknown symbolic types only identify a site;
  // their write width belongs to the processor-specific relocation evaluator.
  const width = table.encoding === "RELR" || table.encoding === "AUTH_RELR" ?
    BigInt(layout.wordSize) : writeSize ?? 1n;
  const section = table.targetSectionIndex == null ? undefined :
    elf.sections[table.targetSectionIndex];
  if (elf.header.type === ELF_FILE_TYPE.REL) {
    return sectionTarget(section, offset, width, elf.fileSize, issues, logicalSizes);
  }
  // GNU ld --emit-relocs retains sh_info for link-time relocations in debug sections.
  // gABI §6 gives linked r_offset as an address, and §3 gives non-ALLOC sections sh_addr=0.
  // https://sourceware.org/binutils/docs/ld/Options.html
  // https://gabi.xinuos.com/elf/06-reloc.html
  if (section && !allocatedSection(section) && !table.sources.some(source => source.startsWith("DT_")) &&
    (elf.header.type === ELF_FILE_TYPE.EXEC || elf.header.type === ELF_FILE_TYPE.DYN)) {
    return sectionTarget(section, offset - section.addr, width, elf.fileSize, issues, logicalSizes);
  }
  return virtualTarget(elf, offset, width, issues);
};
