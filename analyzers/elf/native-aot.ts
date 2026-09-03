"use strict";

import { createFileRangeReader } from "../file-range-reader.js";
import type { NativeAotMetadata } from "../native-aot/format.js";
import { findNativeAotMetadata } from "../native-aot/ready-to-run.js";
import { createElfNativeAotImage } from "./native-aot-image.js";
import { getElfRelativeArchitecture, indexElfNativeAotRelocations } from
  "./native-aot-relocations.js";
import type { ElfHeader, ElfProgramHeader, ElfSectionHeader } from "./types.js";

export const analyzeElfNativeAot = async (
  file: File,
  header: ElfHeader,
  programHeaders: ElfProgramHeader[],
  sections: ElfSectionHeader[],
  is64: boolean,
  littleEndian: boolean,
  issues: string[]
): Promise<NativeAotMetadata | null> => {
  if (header.type !== 2 && header.type !== 3) return null;
  const architecture = getElfRelativeArchitecture(header.machine, is64, littleEndian);
  if (!architecture) return null;
  const reader = createFileRangeReader(file, 0, file.size);
  const provisionalImage = createElfNativeAotImage(
    reader, programHeaders, new Map()
  );
  if (!provisionalImage) return null;
  try {
    const relocations = await indexElfNativeAotRelocations(
      reader,
      programHeaders,
      sections,
      architecture,
      littleEndian,
      provisionalImage,
      issues
    );
    if (!relocations) return null;
    const image = createElfNativeAotImage(
      reader, programHeaders, relocations.targets
    );
    return image ? await findNativeAotMetadata(image, relocations.sites) : null;
  } catch {
    issues.push("ELF NativeAOT relocation data is truncated or malformed.");
    return null;
  }
};
