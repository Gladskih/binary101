import type { ElfHeader, ElfSectionHeader } from "./types.js";

export const ELF_SECTION_ZERO_TYPE_ISSUE = "Section header #0 must have sh_type SHT_NULL.";

// gABI 3.6 and Linux's PN_XNUM extension. Only the corresponding escape
// value gives sh_size, sh_link or sh_info meaning in the reserved entry.
// https://gabi.xinuos.com/elf/03-sheader.html#first-section-header-table-entry
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf.h
const validateSectionZero = (section: ElfSectionHeader, issues: string[], header?: ElfHeader): void => {
  if (section.type !== 0 && !issues.includes(ELF_SECTION_ZERO_TYPE_ISSUE)) {
    issues.push(ELF_SECTION_ZERO_TYPE_ISSUE);
  }
  const fields = [
    ["sh_name", section.nameOff], ["sh_flags", section.flags], ["sh_addr", section.addr],
    ["sh_offset", section.offset], ["sh_addralign", section.addralign], ["sh_entsize", section.entsize]
  ] as const;
  const nonzero = fields.filter(([, value]) => Boolean(value)).map(([name]) => name);
  if (nonzero.length) issues.push(`Section header #0 fields must be zero: ${nonzero.join(", ")}.`);
  if (!header) return;
  if (header.shnum !== 0 && section.size !== 0n) {
    issues.push("Section header #0 sh_size must be zero without extended section numbering.");
  }
  if (header.shstrndx !== 0xffff && section.link !== 0) {
    issues.push("Section header #0 sh_link must be zero without an extended section name table index.");
  }
  if (header.phnum !== 0xffff && section.info !== 0) {
    issues.push("Section header #0 sh_info must be zero without an extended program header count.");
  }
};

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
  sections: ElfSectionHeader[], fileSize: number, issues: string[], header?: ElfHeader
): void => {
  const fileSections: ElfSectionHeader[] = [];
  for (const section of sections) {
    if (section.index === 0) {
      validateSectionZero(section, issues, header);
      continue;
    }
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
