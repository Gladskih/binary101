import { readElfFileHeader } from "./file-header.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { parseProgramHeadersWithGuards, parseSectionHeadersWithNames,
  resolveExtendedHeaderCounts } from "./header-tables.js";
import type { ElfReport } from "./types.js";
import { validateElfLinuxLoadLayout } from "./linux-load-validation.js";
import { validateElfAllocatedSectionMappings } from "./allocated-section-mapping.js";

export async function readElfImageHeaders(file: File): Promise<ElfReport | null> {
  const result = await readElfFileHeader(file);
  if (!result || "incompleteHeader" in result) return result;
  const layout = selectElfBinaryLayout(result);
  const { is64, littleEndian: little, issues } = result;
  const sourceHeader = result.header;
  const header = await resolveExtendedHeaderCounts(file, sourceHeader,
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
  validateElfLinuxLoadLayout(result);
  result.sections = await parseSectionHeadersWithNames(file, header, is64, little, issues,
    layout.sectionHeaderSize, sourceHeader);
  validateElfAllocatedSectionMappings(result);
  return result;
}
