import { readElfFileHeader } from "./file-header.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { parseProgramHeadersWithGuards, parseSectionHeadersWithNames,
  resolveExtendedHeaderCounts } from "./header-tables.js";
import type { ElfReport } from "./types.js";

export async function readElfImageHeaders(file: File): Promise<ElfReport | null> {
  const result = await readElfFileHeader(file);
  if (!result || "incompleteHeader" in result) return result;
  const layout = selectElfBinaryLayout(result);
  const { is64, littleEndian: little, issues } = result;
  const header = await resolveExtendedHeaderCounts(file, result.header,
    is64, little, issues, layout.sectionHeaderSize);
  result.header = header;
  if (header.ehsize < layout.headerSize) {
    issues.push(`ELF header size e_ehsize (${header.ehsize}) is smaller than ` +
      `ELF${is64 ? "64" : "32"} minimum (${layout.headerSize}).`);
    return result;
  }
  if (header.ehsize > file.size) {
    issues.push(`ELF header size e_ehsize (${header.ehsize}) exceeds file size (${file.size}).`);
  }
  result.programHeaders = await parseProgramHeadersWithGuards(file, header, is64, little, issues);
  result.sections = await parseSectionHeadersWithNames(file, header, is64, little, issues, layout.sectionHeaderSize);
  return result;
}
