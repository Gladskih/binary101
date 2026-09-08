"use strict";

import type { ElfNativeAotImage } from "./native-aot-image.js";
import type { ElfRelocation, ElfRelocationInfo, ElfRelocationTable } from "./relocation-types.js";
import type { ElfSectionHeader } from "./types.js";
import type { ElfBinaryLayout } from "./binary-layout-types.js";
import { ELF_MACHINE_ID, ELF_RELATIVE_TYPE, ELF_SECTION_FLAG, ELF_SYMBOL_INDEX } from "./abi-constants.js";

export type ElfRelativeArchitecture = { pointerSize: 8; relocationType: number };

export interface ElfNativeAotRelocations {
  sites: ReadonlySet<number>;
  targets: ReadonlyMap<number, number>;
}

// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/ELFRelocs/x86_64.def
// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/ELFRelocs/AArch64.def
export const getElfRelativeArchitecture = (
  machine: number, layout: ElfBinaryLayout
): ElfRelativeArchitecture | null => {
  // The existing NativeAOT virtual-image reader accepts 64-bit little-endian pointers.
  if (layout.byteOrder !== "little" || layout.wordSize !== 8) return null;
  if (machine === ELF_MACHINE_ID.X86_64) return { pointerSize: 8, relocationType: ELF_RELATIVE_TYPE.X86_64 };
  if (machine === ELF_MACHINE_ID.AARCH64) return { pointerSize: 8, relocationType: ELF_RELATIVE_TYPE.AARCH64 };
  return null;
};

const relativeTarget = async (
  entry: ElfRelocation, architecture: ElfRelativeArchitecture, image: ElfNativeAotImage
): Promise<[number, number] | null> => {
  const site = image.toImageAddress(entry.offset);
  if (site == null || !image.isDataRange(site, architecture.pointerSize, architecture.pointerSize)) {
    return null;
  }
  const address = entry.addend ?? await image.readPointerValue(site);
  if (address == null || address < 0n) return null;
  const target = image.toImageAddress(address);
  return target == null ? null : [site, target];
};

const isRelativeEvidence = (
  entry: ElfRelocation, table: ElfRelocationTable, allocated: Set<number>,
  architecture: ElfRelativeArchitecture
): boolean => {
  const loaded = table.sectionIndex == null || allocated.has(table.sectionIndex) ||
    table.sources.some(source => source.startsWith("DT_"));
  return loaded && (table.encoding === "RELR" ||
    (entry.type === architecture.relocationType && entry.symbolIndex === ELF_SYMBOL_INDEX.UNDEF));
};

export const indexElfNativeAotRelocations = async (
  relocations: ElfRelocationInfo | null, sections: ElfSectionHeader[],
  architecture: ElfRelativeArchitecture, image: ElfNativeAotImage, issues: string[]
): Promise<ElfNativeAotRelocations | null> => {
  if (!relocations) return null;
  const allocated = new Set(sections.filter(section => section.flags & ELF_SECTION_FLAG.ALLOC)
    .map(section => section.index));
  const targets = new Map<number, number>();
  for (const entry of relocations.entries) {
    const table = relocations.tables[entry.tableIndex]!;
    if (!isRelativeEvidence(entry, table, allocated, architecture)) continue;
    const relocation = await relativeTarget(entry, architecture, image);
    if (!relocation) continue;
    const existing = targets.get(relocation[0]);
    if (existing != null && existing !== relocation[1]) {
      issues.push("Conflicting ELF relative relocations prevent reliable NativeAOT analysis.");
      return null;
    }
    targets.set(relocation[0], relocation[1]);
  }
  return targets.size ? { sites: new Set(targets.keys()), targets } : null;
};
