import { ELF_SECTION_FLAG, ELF_SECTION_TYPE, ELF_SEGMENT_TYPE } from "./abi-constants.js";
import { elfFileRange } from "./relocation-reader.js";
import { createElfRangeCoverage } from "./range-coverage.js";
import { elfLinuxLoadProfile } from "./linux-load-validation.js";
import type { ElfParseResult, ElfProgramHeader, ElfSectionHeader } from "./types.js";

const makeFileMappings = (loads: ElfProgramHeader[]) => {
  const ranges = new Map<bigint, { start: bigint; end: bigint }[]>();
  for (const load of loads) {
    if (load.filesz > load.memsz) continue;
    const translation = load.vaddr - load.offset;
    const range = { start: load.offset, end: load.offset + load.filesz };
    const existing = ranges.get(translation);
    if (existing) existing.push(range);
    else ranges.set(translation, [range]);
  }
  return new Map(Array.from(ranges, ([translation, group]) => [translation, createElfRangeCoverage(group)]));
};

const isLoadableSection = (section: ElfSectionHeader): boolean => section.size > 0n && section.type !== 0 &&
  (section.flags & ELF_SECTION_FLAG.ALLOC) !== 0n && (section.flags & ELF_SECTION_FLAG.TLS) === 0n;

// gABI 3.4 and 7.2: SHF_ALLOC occupies the process image and SHT_NOBITS
// occupies memory only. SHF_TLS is validated against the separate TLS template.
// https://gabi.xinuos.com/elf/03-sheader.html#section-flags
// https://gabi.xinuos.com/elf/07-pheader.html#segment-types
export const validateElfAllocatedSectionMappings = (image: ElfParseResult): void => {
  if (!elfLinuxLoadProfile(image.ident, image.header) || image.programHeaders.length !== image.header.phnum) return;
  const loads = image.programHeaders.filter(header => header.type === ELF_SEGMENT_TYPE.LOAD);
  if (!loads.length) return;
  const mappedMemory = createElfRangeCoverage(loads.map(load => ({ start: load.vaddr, end: load.vaddr + load.memsz })));
  const mappedFiles = makeFileMappings(loads);
  for (const section of image.sections.filter(isLoadableSection)) {
    if (section.type === ELF_SECTION_TYPE.NOBITS) {
      if (!mappedMemory(section.addr, section.addr + section.size)) {
        image.issues.push(`Allocated SHT_NOBITS section #${section.index} is outside PT_LOAD memory.`);
      }
    } else if (elfFileRange(section.offset, section.size, image.fileSize) &&
        !mappedFiles.get(section.addr - section.offset)?.(section.offset, section.offset + section.size)) {
      image.issues.push(`Allocated section #${section.index} lacks file-backed PT_LOAD coverage at sh_addr.`);
    }
  }
};
