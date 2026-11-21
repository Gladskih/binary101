import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import { DwarfCursor } from "../dwarf/cursor.js";
import type { ElfParseResult, ElfSectionHeader } from "./types.js";
import type { ElfAttributeSection } from "./attribute-types.js";
import { elfFileRange } from "./relocation-reader.js";
import { readElfAttributeVendor } from "./attribute-scopes.js";
import { readAarch64AttributeSubsection } from "./aarch64-attributes.js";

const readAttributeSection = async (
  reader: FileRangeReader, section: ElfSectionHeader, elf: ElfParseResult
): Promise<ElfAttributeSection> => {
  const result: ElfAttributeSection = { sectionIndex: section.index, vendors: [], issues: [] };
  const range = elfFileRange(section.offset, section.size, reader.size);
  if (!range || (section.flags & 0x800n)) {
    result.issues.push("Attributes section is compressed, truncated or outside the file.");
    return result;
  }
  const cursorAt = (position: number, end: number) => new DwarfCursor(reader,
    { ...range, name: section.name ?? ".attributes", compressed: false }, position, end,
    elf.littleEndian, result.issues);
  const cursor = cursorAt(0, range.size);
  if (await cursor.uint8() !== 65) {
    cursor.fail("Unsupported attributes format version; expected A");
    return result;
  }
  const readSubsection = elf.header.machine === 183 ? readAarch64AttributeSubsection : readElfAttributeVendor;
  const names = new Set<string>();
  while (cursor.position < cursor.end && !cursor.failed) {
    const vendor = await readSubsection(cursor, cursorAt);
    if (!vendor) break;
    if (vendor.aarch64 && names.has(vendor.name)) cursor.notice(`Duplicate AArch64 subsection ${vendor.name}`);
    names.add(vendor.name);
    result.vendors.push(vendor);
  }
  return result;
};

export const parseElfAttributes = async (file: File, elf: ElfParseResult): Promise<ElfAttributeSection[]> => {
  // ARM, AArch64 and RISC-V attributes use processor-specific type 0x70000003.
  // https://github.com/ARM-software/abi-aa/blob/main/buildattr64/buildattr64.rst
  if (![40, 183, 243].includes(elf.header.machine)) return [];
  const reader = createFileRangeReader(file, 0, file.size);
  const results: ElfAttributeSection[] = [];
  for (const section of elf.sections.filter(item => item.type === 0x70000003)) {
    results.push(await readAttributeSection(reader, section, elf));
  }
  return results;
};
