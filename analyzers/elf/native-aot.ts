"use strict";

import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import type { NativeAotMetadata } from "../native-aot/format.js";
import { findNativeAotMetadata } from "../native-aot/ready-to-run.js";
import { createElfNativeAotImage, type ElfNativeAotImage } from "./native-aot-image.js";
import { getElfRelativeArchitecture, indexElfNativeAotRelocations, type ElfRelativeArchitecture } from
  "./native-aot-relocations.js";
import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";
import type { ElfRelocationImage, ElfRelocationInfo } from "./relocation-types.js";
import { parseElfRelocations } from "./relocations.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { ELF_FILE_TYPE } from "./abi-constants.js";

const analyzeRelocatedImage = async (
  reader: FileRangeReader, programHeaders: ElfProgramHeader[], sections: ElfSectionHeader[],
  architecture: ElfRelativeArchitecture, provisionalImage: ElfNativeAotImage,
  general: ElfRelocationInfo | null, issues: string[]
): Promise<NativeAotMetadata | null> => {
  // Metadata confirmation requires complete, unambiguous relocation evidence.
  if (general?.issues.length) return null;
  const relocations = await indexElfNativeAotRelocations(
    general, sections, architecture, provisionalImage, issues);
  if (!relocations) return null;
  const image = createElfNativeAotImage(reader, programHeaders, relocations.targets);
  // Visit nearby targets together so the bounded range cache can reuse their bytes.
  const orderedSites = new Set([...relocations.sites].sort((left, right) =>
    relocations.targets.get(left)! - relocations.targets.get(right)!));
  return image ? await findNativeAotMetadata(image, orderedSites) : null;
};

export const analyzeElfNativeAot = async (
  file: File,
  elf: ElfRelocationImage,
  issues: string[],
  parsedRelocations?: ElfRelocationInfo | null,
  layout = selectElfBinaryLayout(elf)
): Promise<NativeAotMetadata | null> => {
  if (elf.header.type !== ELF_FILE_TYPE.EXEC && elf.header.type !== ELF_FILE_TYPE.DYN) return null;
  const architecture = getElfRelativeArchitecture(elf.header.machine, layout);
  if (!architecture) return null;
  const reader = createFileRangeReader(file, 0, file.size);
  const provisionalImage = createElfNativeAotImage(
    reader, elf.programHeaders, new Map()
  );
  if (!provisionalImage) return null;
  try {
    const general = parsedRelocations === undefined ?
      await parseElfRelocations(file, elf, undefined, undefined, layout) : parsedRelocations;
    return await analyzeRelocatedImage(
      reader, elf.programHeaders, elf.sections, architecture, provisionalImage, general, issues);
  } catch {
    issues.push("ELF NativeAOT relocation data is truncated or malformed.");
    return null;
  }
};
