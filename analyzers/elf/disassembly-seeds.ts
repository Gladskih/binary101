"use strict";

import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";
import type { ElfDisassemblySeedGroup } from "./disassembly-seeds-types.js";
import { collectElfDisassemblySeedsFromSections } from "./disassembly-seeds-sections.js";
import { collectElfDisassemblySeedsFromDynamic } from "./disassembly-seeds-dynamic.js";
import { collectElfDisassemblySeedsFromEhFrameHdr } from "./disassembly-seeds-eh-frame-hdr.js";

export async function collectElfDisassemblySeedGroups(opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
  issues: string[];
}): Promise<ElfDisassemblySeedGroup[]> {
  const groups: ElfDisassemblySeedGroup[] = [];
  groups.push(
    ...(await collectElfDisassemblySeedsFromDynamic(opts).catch(() => [])),
    ...(await collectElfDisassemblySeedsFromSections(opts).catch(() => [])),
    ...(await collectElfDisassemblySeedsFromEhFrameHdr(opts).catch(() => []))
  );
  return groups;
}

