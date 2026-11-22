import type { ElfSectionHeader } from "./types.js";

const validateSectionOverlap = (fileSections: ElfSectionHeader[], issues: string[]): void => {
  fileSections.sort((left, right) =>
    left.offset < right.offset ? -1 : Number(left.offset > right.offset));
  let previous: ElfSectionHeader | undefined;
  let coveredEnd = 0n;
  for (const section of fileSections) {
    if (previous && section.offset < coveredEnd) {
      issues.push(`Section #${section.index} file range overlaps section #${previous.index}.`);
    }
    const end = section.offset + section.size;
    if (end > coveredEnd) {
      previous = section;
      coveredEnd = end;
    }
  }
};

// gABI 3.2/3.3: SHT_NULL has no payload; SHT_NOBITS occupies no file bytes.
// sh_addralign is zero or a power of two, and sh_addr must satisfy it.
// https://gabi.xinuos.com/elf/03-sheader.html
export const validateElfSectionHeaders = (
  sections: ElfSectionHeader[], fileSize: number, issues: string[]
): void => {
  const fileSections: ElfSectionHeader[] = [];
  for (const section of sections) {
    if (section.type === 0) continue;
    if (section.type !== 8 && section.size > 0n) {
      if (section.offset + section.size > BigInt(fileSize)) {
        issues.push(`Section #${section.index} file range is outside the file.`);
      }
      if (section.offset < BigInt(fileSize)) fileSections.push(section);
    }
    if (section.addralign <= 1n) continue;
    if ((section.addralign & (section.addralign - 1n)) !== 0n) {
      issues.push(`Section #${section.index}: sh_addralign is not a power of two.`);
    }
    if (section.addr % section.addralign !== 0n) {
      issues.push(`Section #${section.index}: sh_addr does not satisfy sh_addralign.`);
    }
  }
  validateSectionOverlap(fileSections, issues);
};
