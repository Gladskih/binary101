import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfRelocation, ElfRelocationImage, ElfRelocationTable } from "./relocation-types.js";
import { readElfRelocationRecords } from "./relocation-records.js";
import { ELF_SECTION_COMPRESSED, openElfSectionData } from "./section-data.js";

export async function* readElfCompressedRelocations(
  reader: FileRangeReader, table: ElfRelocationTable, elf: ElfRelocationImage,
  tableIndex: number, issues: string[]
): AsyncGenerator<ElfRelocation> {
  const section = elf.sections.find(section => section.index === table.sectionIndex);
  if (!section || !(section.flags & ELF_SECTION_COMPRESSED)) {
    issues.push("Compressed relocation section header is missing or inconsistent.");
    return;
  }
  const source = await openElfSectionData(reader, section, elf, issues);
  if (!source) return;
  const decoded = { ...table, offset: source.offset, size: source.size };
  delete decoded.compressed;
  yield* readElfRelocationRecords(source.reader, decoded, elf, tableIndex, issues);
  table.complete = decoded.complete === true;
}
