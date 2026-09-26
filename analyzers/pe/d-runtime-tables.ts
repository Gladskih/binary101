import type { PeBaseRelocationResult } from "./directories/reloc.js";
import type { PeSection, PeWindowsCore } from "./types.js";
import { COFF_SECTION_CHARACTERISTICS } from "../coff/layout.js";
import {
  BASE_RELOCATION_PAGE_SIZE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW
} from "./directories/reloc.js";

const isPointerTableSection = (section: PeSection, core: PeWindowsCore,
  pointerSize: number): boolean =>
  // At least two independent records are needed for structural confirmation.
  section.virtualSize >= 2 * pointerSize &&
  section.virtualSize <= section.sizeOfRawData && section.virtualSize % pointerSize === 0 &&
  (section.characteristics &
    (COFF_SECTION_CHARACTERISTICS.MEM_EXECUTE | COFF_SECTION_CHARACTERISTICS.MEM_READ |
      COFF_SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)) ===
    (COFF_SECTION_CHARACTERISTICS.MEM_READ | COFF_SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA) &&
  !core.dataDirs.some(directory => directory.name !== "SECURITY" && directory.size > 0 &&
    directory.rva < section.virtualAddress + section.virtualSize &&
    directory.rva + directory.size > section.virtualAddress);

const relocatedSlots = (section: PeSection, relocations: PeBaseRelocationResult,
  pointerSize: number): Set<number> => {
  const slots = new Set<number>();
  for (const block of relocations.blocks) {
    if (block.pageRva + BASE_RELOCATION_PAGE_SIZE <= section.virtualAddress ||
      block.pageRva >= section.virtualAddress + section.virtualSize) continue;
    for (const entry of block.entries) {
      const relative = block.pageRva + entry.offset - section.virtualAddress;
      if (isRelocatedSlot(entry.type, relative, section.virtualSize, pointerSize)) {
        slots.add(relative);
        if (slots.size === 2) return slots;
      }
    }
  }
  return slots;
};

const isRelocatedSlot = (type: number, relative: number, size: number,
  pointerSize: number): boolean =>
  type === (pointerSize === 8 ? IMAGE_REL_BASED_DIR64 : IMAGE_REL_BASED_HIGHLOW) &&
  relative >= 0 && relative + pointerSize <= size && relative % pointerSize === 0;

export const findDModuleTableCandidates = (core: PeWindowsCore,
  relocations: PeBaseRelocationResult | null, pointerSize: 4 | 8)
  : Array<{ section: PeSection; firstPointerOffset: number }> => {
  // Renamed tables without relocations cannot be found by this structural strategy.
  if (!relocations || relocations.warnings?.length) return [];
  // Locate an anchor for a sparse probe; never scan a large non-D section first.
  // NULL padding is permitted anywhere by druntime, so no density is assumed.
  return core.sections.filter(section => isPointerTableSection(section, core, pointerSize))
    .flatMap(section => {
      const slots = relocatedSlots(section, relocations, pointerSize);
      return slots.size === 2 ? [{ section, firstPointerOffset: slots.values().next().value! }] : [];
    });
};
