"use strict";

import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { nativeAotSectionName, type NativeAotMetadata } from "../native-aot/format.js";
import { getElfImageBase } from "./native-aot-image.js";
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
  nativeAot?: NativeAotMetadata | null;
}): Promise<ElfDisassemblySeedGroup[]> {
  const groups: ElfDisassemblySeedGroup[] = [];
  const imageBase = getElfImageBase(opts.programHeaders);
  if (imageBase != null) {
    for (const table of opts.nativeAot?.initializers ?? []) {
      groups.push({
        source: `NativeAOT ${nativeAotSectionName(table.sectionType)}`,
        vaddrs: table.targetRvas.map(rva => imageBase + BigInt(rva))
      });
    }
  }
  groups.push(
    ...(await collectElfDisassemblySeedsFromDynamic(opts).catch(() => [])),
    ...(await collectElfDisassemblySeedsFromSections(opts).catch(() => [])),
    ...(await collectElfDisassemblySeedsFromEhFrameHdr(opts).catch(() => []))
  );
  return groups;
}

