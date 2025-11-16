"use strict";

export function computeEntrySection(opt, sections) {
  if (!opt.AddressOfEntryPoint) return null;
  const entryRva = opt.AddressOfEntryPoint >>> 0;
  for (let index = 0; index < sections.length; index++) {
    const section = sections[index];
    const start = section.virtualAddress >>> 0;
    const end = (start + (section.virtualSize >>> 0)) >>> 0;
    if (entryRva >= start && entryRva < end) {
      return { name: section.name, index };
    }
  }
  return null;
}

