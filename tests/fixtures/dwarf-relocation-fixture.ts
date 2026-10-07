import { dwarfMacroSources } from "./dwarf-macro-fixture.js";
import { relocationFixture, relocationSection } from "./elf-relocations.js";
import type { DwarfSectionSource } from "../../analyzers/dwarf/types.js";
import type { ElfRelocationInfo } from "../../analyzers/elf/relocation-types.js";

export const createDwarfRelocationFixture = (bytes = new Array<number>(16).fill(0),
  byteOrder: "little" | "big" = "little", bits: 32 | 64 = 64) => {
  const source: DwarfSectionSource = dwarfMacroSources([{ name: ".debug_info", bytes }]).get(".debug_info")!;
  const elf = relocationFixture(bits, byteOrder).elf;
  elf.sections = [relocationSection(1, { name: ".debug_info", size: BigInt(bytes.length) })];
  const relocations: ElfRelocationInfo = { tables: [{ offset: 0, size: 24, entrySize: 24,
    encoding: "RELA", sources: [], sectionIndex: 2, symbolTableIndex: 3, targetSectionIndex: 1 }],
  entries: [{ tableIndex: 0, recordOffset: 0, offset: 4n, type: 10, symbolIndex: 1,
    symbol: { name: "target", value: 12n, sectionIndex: 1 }, addend: 4n,
    target: { sectionIndex: 1, sectionOffset: 4n, fileOffset: 4n } }], issues: [] };
  source.summary = { ...source.summary, requiresRelocations: true };
  source.decoded = false;
  return { source, elf, relocations, issues: [] as string[] };
};
