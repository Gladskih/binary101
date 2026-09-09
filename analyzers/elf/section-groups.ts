import { createFileRangeReader } from "../file-range-reader.js";
import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfParseResult, ElfSectionHeader } from "./types.js";
import { elfFileRange } from "./relocation-reader.js";

export interface ElfSectionGroup {
  sectionIndex: number;
  flags: number | null;
  members: number[];
  issues: string[];
}

// gABI 3.9: group words are 32 bits for both classes, including the first flag word.
// https://gabi.xinuos.com/elf/03-sheader.html#section-groups
const validateGroupHeader = (
  section: ElfSectionHeader, elf: ElfParseResult, issues: string[]
): void => {
  if (elf.header.type !== 1) issues.push("Section groups are only defined for relocatable ELF files.");
  const symbols = elf.sections.find(item => item.index === section.link && item.type === 2);
  if (!symbols || symbols.entsize <= 0n || BigInt(section.info + 1) * symbols.entsize > symbols.size) {
    issues.push("Group signature has an invalid symbol table reference.");
  }
  if (section.flags !== 0n) issues.push("Group section header has nonzero flags.");
};

const validateMember = (
  index: number, section: ElfSectionHeader | undefined, group: ElfSectionGroup,
  memberships: Set<number>
): void => {
  if (!index || !section || section.type === 17) {
    group.issues.push(`Invalid group member section #${index}.`);
    return;
  }
  if (!(section.flags & 0x200n)) group.issues.push(`Member #${index} lacks SHF_GROUP.`);
  if (memberships.has(index)) group.issues.push(`Member #${index} already belongs to a group.`);
  memberships.add(index);
};

const readSectionGroup = async (
  reader: FileRangeReader, elf: ElfParseResult, section: ElfSectionHeader,
  memberships: Set<number>, sections: Map<number, ElfSectionHeader>
): Promise<ElfSectionGroup> => {
  const group: ElfSectionGroup = { sectionIndex: section.index, flags: null, members: [], issues: [] };
  validateGroupHeader(section, elf, group.issues);
  const range = groupRange(section, reader.size, group.issues);
  if (!range) return group;
  const header = await reader.read(range.offset, 4);
  if (header.byteLength < 4) {
    group.issues.push("Group flag word is truncated.");
    return group;
  }
  group.flags = header.getUint32(0, elf.littleEndian);
  if ((group.flags & ~0xfff00001) !== 0) group.issues.push("Group has unknown flags.");
  // More members than sections cannot be valid; avoid retaining unbounded duplicate indices.
  const count = Math.min(range.size / 4 - 1, elf.sections.length);
  if (count !== range.size / 4 - 1) group.issues.push("Group member count exceeds the section count.");
  for (let index = 0; index < count; index += 1) {
    const view = await reader.read(range.offset + 4 + index * 4, 4);
    if (view.byteLength < 4) {
      group.issues.push("Group member data is truncated.");
      break;
    }
    const member = view.getUint32(0, elf.littleEndian);
    validateMember(member, sections.get(member), group, memberships);
    group.members.push(member);
  }
  return group;
};

const groupRange = (
  section: ElfSectionHeader, fileSize: number, issues: string[]
): { offset: number; size: number } | null => {
  const range = elfFileRange(section.offset, section.size, fileSize);
  if (!range) {
    issues.push("Group data is outside the file.");
    return null;
  }
  if (section.entsize !== 4n || range.size < 4 || range.size % 4) {
    issues.push("Group data has an invalid size or entry size.");
    return null;
  }
  return range;
};

export const parseElfSectionGroups = async (
  file: File, elf: ElfParseResult
): Promise<ElfSectionGroup[]> => {
  const reader = createFileRangeReader(file, 0, file.size);
  const memberships = new Set<number>();
  const sections = new Map(elf.sections.map(section => [section.index, section]));
  const groups: ElfSectionGroup[] = [];
  for (const section of elf.sections.filter(item => item.type === 17)) {
    groups.push(await readSectionGroup(reader, elf, section, memberships, sections));
  }
  return groups;
};
