"use strict";

import type { PeOptionalHeader, PeSection } from "./types.js";

const getMappedSectionSpan = (section: PeSection): number =>
  (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);

export function computeEntrySection(
  opt: Pick<PeOptionalHeader, "AddressOfEntryPoint">,
  sections: PeSection[]
): { name: string; index: number } | null {
  if (!opt.AddressOfEntryPoint) return null;
  const entryRva = opt.AddressOfEntryPoint >>> 0;
  for (let index = 0; index < sections.length; index += 1) {
    const section = sections[index];
    if (!section) continue;
    const start = section.virtualAddress >>> 0;
    const span = getMappedSectionSpan(section);
    const end = (start + span) >>> 0;
    if (entryRva >= start && entryRva < end) {
      return { name: section.name, index };
    }
  }
  return null;
}
