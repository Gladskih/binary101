"use strict";

import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { nativeAotSectionName, type NativeAotMetadata } from "../native-aot/format.js";
import { getElfImageBase } from "./native-aot-image.js";
import type { ElfDisassemblySeedGroup } from "./disassembly-seeds-types.js";
import { collectElfDisassemblySeedsFromSections } from "./disassembly-seeds-sections.js";
import { collectElfDisassemblySeedsFromDynamic } from "./disassembly-seeds-dynamic.js";
import { collectElfDisassemblySeedsFromEhFrameHdr } from "./disassembly-seeds-eh-frame-hdr.js";
import { collectGoFunctionSeeds } from "./go-function-seeds.js";
import { collectNativeAotMapSeeds } from "../native-aot/disassembly-seeds.js";
import type { ElfSFrame } from "./sframe-types.js";
import { sframeFunctionAddress } from "./sframe-layout.js";

const collectSFrameSeeds = (tables: ElfSFrame[]): bigint[] => {
  const vaddrs: bigint[] = [];
  for (const table of tables) {
    for (const entry of table.functions) {
      if (entry.size === 0 || entry.issues.length > 0) continue;
      const address = sframeFunctionAddress(table, entry);
      if (address != null) vaddrs.push(address);
    }
  }
  return vaddrs;
};

export async function collectElfDisassemblySeedGroups(opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
  issues: string[];
  nativeAot?: NativeAotMetadata | null;
  sframe?: ElfSFrame[];
}): Promise<ElfDisassemblySeedGroup[]> {
  const groups: ElfDisassemblySeedGroup[] = [];
  const imageBase = getElfImageBase(opts.programHeaders);
  if (imageBase != null) {
    for (const group of opts.nativeAot ? collectNativeAotMapSeeds(opts.nativeAot) : []) {
      groups.push({ source: group.source, vaddrs: group.rvas.map(rva => imageBase + BigInt(rva)) });
    }
    for (const table of opts.nativeAot?.initializers ?? []) {
      groups.push({
        source: `NativeAOT ${nativeAotSectionName(table.sectionType)}`,
        vaddrs: table.targetRvas.map(rva => imageBase + BigInt(rva))
      });
    }
  }
  groups.push(
    ...(await collectGoFunctionSeeds(opts.file, opts.sections, opts.issues)),
    ...(await collectElfDisassemblySeedsFromDynamic(opts).catch(() => [])),
    ...(await collectElfDisassemblySeedsFromSections(opts).catch(() => [])),
    ...(await collectElfDisassemblySeedsFromEhFrameHdr(opts).catch(() => []))
  );
  const sframe = collectSFrameSeeds(opts.sframe ?? []);
  if (sframe.length) groups.push({ source: "SFrame function descriptors", vaddrs: sframe });
  return groups;
}

