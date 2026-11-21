import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";

// gABI 7.5 and 7.7: the TLS NOBITS tail belongs to the TLS template.
// https://gabi.xinuos.com/elf/07-pheader.html
const isSectionInSegment = (section: ElfSectionHeader, segment: ElfProgramHeader): boolean => {
  const tls = (section.flags & 0x400n) !== 0n;
  const zeroFill = section.type === 8;
  const allocated = (section.flags & 2n) !== 0n;
  const fileOffset = section.offset - segment.offset;
  const virtualOffset = section.addr - segment.vaddr;
  if (segment.type === 7 && !tls) return false;
  if (tls && zeroFill && segment.type !== 7) return false;
  if ((segment.type === 4 || segment.type === 0x6474e553) && section.type !== 7) return false;
  if (!allocated && segment.type !== 4) return false;
  if (allocated && (virtualOffset < 0n || virtualOffset + section.size > segment.memsz)) return false;
  if (zeroFill) return segment.type === 1 || segment.type === 7;
  return fileOffset >= 0n && fileOffset + section.size <= segment.filesz &&
    (!allocated || fileOffset === virtualOffset);
};

export const elfSectionSegments = (
  section: ElfSectionHeader, headers: ElfProgramHeader[]
): ElfProgramHeader[] => {
  if (!section.type || !section.size) return [];
  // Standard data segments and the GNU program headers that designate file/memory ranges.
  // https://github.com/bminor/glibc/blob/master/elf/elf.h
  return headers.filter(segment => [1, 2, 3, 4, 7, 0x6474e550, 0x6474e552, 0x6474e553]
    .includes(segment.type) && isSectionInSegment(section, segment));
};
