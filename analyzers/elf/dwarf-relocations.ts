import type { DwarfSectionSource } from "../dwarf/types.js";
import type { ElfRelocationInfo, ElfRelocationImage } from "./relocation-types.js";
import { buildElfDwarfRelocationPatches } from "./dwarf-relocation-patches.js";
import { elfDwarfRelocationOverlay } from "./dwarf-relocation-overlay.js";

const relocateSource = async (source: DwarfSectionSource, elf: ElfRelocationImage,
  relocations: ElfRelocationInfo, issues: string[]): Promise<DwarfSectionSource> => {
  if (!validSourceOffset(source)) {
    issues.push("DWARF relocation source has an invalid file offset.");
    return { ...source, decoded: false };
  }
  const section = elf.sections.find(section => section.name === source.summary.name &&
    section.offset === BigInt(source.summary.offset));
  if (!section || !source.summary.requiresRelocations || source.section.compressed) return source;
  const tables = relocations.tables.map((table, index) => ({ table, index }))
    .filter(({ table }) => table.targetSectionIndex === section.index);
  if (!tables.length) return { ...source, decoded: false };
  const indexes = new Set(tables.map(({ index }) => index));
  const entries = relocations.entries.filter(entry => indexes.has(entry.tableIndex));
  const expected = tables.reduce((count, { table }) => count + table.size / table.entrySize, 0);
  if (!Number.isSafeInteger(expected) || entries.length !== expected) {
    issues.push(`${section.name}: relocation records are incomplete; section is not decoded.`);
    return { ...source, decoded: false };
  }
  const patches = await buildElfDwarfRelocationPatches(source, entries, elf, issues);
  if (!patches) return { ...source, decoded: false };
  const summary = { ...source.summary };
  delete summary.requiresRelocations;
  return { ...source, summary, section: { ...source.section, requiresRelocations: false },
    reader: elfDwarfRelocationOverlay(source.reader, patches), decoded: true };
};

const validSourceOffset = (source: DwarfSectionSource): boolean =>
  Number.isSafeInteger(source.summary.offset) && source.summary.offset >= 0;

export const applyElfDwarfRelocations = async (sources: DwarfSectionSource[], elf: ElfRelocationImage,
  relocations: ElfRelocationInfo, issues: string[]): Promise<DwarfSectionSource[]> => {
  const relocated: DwarfSectionSource[] = [];
  for (const source of sources) relocated.push(await relocateSource(source, elf, relocations, issues));
  return relocated;
};
