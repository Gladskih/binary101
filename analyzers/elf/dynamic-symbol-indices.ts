import { createFileRangeReader } from "../file-range-reader.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { elfFileRange, elfVirtualRange } from "./relocation-reader.js";
import type { ElfDynamicEntry } from "./dynamic-entries.js";
import type { ElfRelocationImage } from "./relocation-types.js";
import { ELF_SECTION_COMPRESSED, openElfSectionData, type ElfSectionData,
  type ElfSectionEncoding } from "./section-data.js";

// gABI 5.5 / 8.3: SHN_XINDEX=0xffff, SHT_SYMTAB_SHNDX=18,
// DT_SYMTAB_SHNDX=34; extended indices are Elf32_Word in both ELF classes.
// https://gabi.xinuos.com/elf/05-symtab.html#section-index
// https://gabi.xinuos.com/elf/08-dynamic.html
export const createElfDynamicIndexReader = (
  file: File, elf: Pick<ElfRelocationImage, "sections" | "programHeaders"> & ElfSectionEncoding,
  tableOffset: number, entries: ElfDynamicEntry[], issues: string[]
): ((index: number, sectionIndex: number) => Promise<number | null>) => {
  const reader = createFileRangeReader(file, 0, file.size);
  const layout = selectElfBinaryLayout(elf);
  const symbols = elf.sections.find(section => section.type === 11 &&
    section.offset === BigInt(tableOffset));
  const extended = symbols && elf.sections.find(section => section.type === 18 &&
    section.link === symbols.index);
  const address = entries.find(entry => entry.tag === 34)?.value;
  let decoded: Promise<ElfSectionData | null> | undefined;
  return async (index, sectionIndex) => {
    if (sectionIndex !== 0xffff) return sectionIndex;
    const relative = BigInt(index) * 4n;
    const compressed = extended && (extended.flags & ELF_SECTION_COMPRESSED) !== 0n;
    const data = compressed
      ? await (decoded ??= openElfSectionData(reader, extended, elf, issues)) : null;
    const range = compressed
      ? data && extended.entsize === 4n && relative + 4n <= BigInt(data.size)
        ? { offset: data.offset + Number(relative) } : null
      : extended
      ? extended.entsize === 4n && relative + 4n <= extended.size
        ? elfFileRange(extended.offset + relative, 4n, file.size) : null
      : address != null ? elfVirtualRange(elf.programHeaders, address + relative, 4n, file.size)
        : null;
    const value = range ? layout.readSectionIndex(await (data?.reader ?? reader).read(range.offset, 4)) : null;
    // Actual extended indices must be at least SHN_LORESERVE (gABI 3.1).
    if (value != null && value >= 0xff00) return value;
    issues.push(`Dynamic symbol #${index} has an invalid SHN_XINDEX reference.`);
    return null;
  };
};
