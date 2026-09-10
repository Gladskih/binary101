import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import { DwarfCursor } from "../dwarf/cursor.js";
import type { ElfParseResult, ElfSectionHeader } from "./types.js";
import type { ElfAttributeSection } from "./attribute-types.js";
import { elfFileRange } from "./relocation-reader.js";
import { readElfAttributeVendor } from "./attribute-scopes.js";

const readAttributeSection = async (
  reader: FileRangeReader, section: ElfSectionHeader, byteOrder: "little" | "big"
): Promise<ElfAttributeSection> => {
  const result: ElfAttributeSection = { sectionIndex: section.index, vendors: [], issues: [] };
  const range = elfFileRange(section.offset, section.size, reader.size);
  if (!range || (section.flags & 0x800n)) {
    result.issues.push("Attributes section is compressed, truncated or outside the file.");
    return result;
  }
  const cursorAt = (position: number, end: number) => new DwarfCursor(reader,
    { ...range, name: section.name ?? ".attributes", compressed: false }, position, end,
    byteOrder === "little", result.issues);
  const cursor = cursorAt(0, range.size);
  if (await cursor.uint8() !== 65) {
    cursor.fail("Unsupported attributes format version; expected A");
    return result;
  }
  while (cursor.position < cursor.end && !cursor.failed) {
    const vendor = await readElfAttributeVendor(cursor, cursorAt);
    if (!vendor) break;
    result.vendors.push(vendor);
    if (result.vendors.length === 100000) cursor.fail("Attribute vendor limit reached");
  }
  return result;
};

export const parseElfAttributes = async (file: File, elf: ElfParseResult): Promise<ElfAttributeSection[]> => {
  // SHT_ARM_ATTRIBUTES and SHT_RISCV_ATTRIBUTES both use processor-specific type 0x70000003.
  if (![40, 243].includes(elf.header.machine)) return [];
  const reader = createFileRangeReader(file, 0, file.size);
  const results: ElfAttributeSection[] = [];
  for (const section of elf.sections.filter(item => item.type === 0x70000003)) {
    results.push(await readAttributeSection(reader, section, elf.littleEndian ? "little" : "big"));
  }
  return results;
};
