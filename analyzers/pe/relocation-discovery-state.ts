import type { FileRangeReader } from "../file-range-reader.js";
import type { PeBaseRelocationResult } from "./directories/reloc.js";
import { collectPeItaniumRelocationSites } from "./itanium-rtti.js";
import { createPeItaniumImage } from "./itanium-rtti-image.js";
import { createMsvcRttiImage, type MsvcRttiImage } from "./msvc-rtti/image.js";
import type { MsvcRttiCandidate } from "./msvc-rtti/discovery.js";
import { indexMsvcRttiDir64Sites } from "./msvc-rtti/relocation-index.js";
import {
  createPeNativeAotImage, getPeNativeAotArchitecture, indexPeNativeAotPointerSites,
  type PeNativeAotImage
} from "./native-aot/image.js";
import type { ItaniumRttiImage } from "../itanium-rtti/types.js";
import type { PeWindowsCore } from "./types.js";
import { COFF_FILE_CHARACTERISTICS } from "../coff/layout.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "./layout/rva-limits.js";

export interface PeRelocationDiscovery {
  reader: FileRangeReader;
  nativeImage: PeNativeAotImage;
  msvcImage: MsvcRttiImage | null;
  itaniumImage: ItaniumRttiImage;
  sites: number[];
  nativeSites: Set<number>;
  msvcSites: Set<number>;
  nativeCandidates: Map<number, number>;
  msvcCandidates: MsvcRttiCandidate[];
  boundarySites: number[];
}

const hasSharedMapping = (reader: FileRangeReader, core: PeWindowsCore): boolean =>
  core.sections.every(section => {
    // PE/COFF: initialized, readable data without IMAGE_SCN_MEM_EXECUTE.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
    if ((section.characteristics & 0x60000040) !== 0x40000040) return true;
    const size = Math.min(section.virtualSize || section.sizeOfRawData,
      section.sizeOfRawData, Math.max(0, reader.size - section.pointerToRawData));
    if (size === 0) return true;
    return core.rvaToOff(section.virtualAddress) === section.pointerToRawData &&
      core.rvaToOff(section.virtualAddress + size - 1) === section.pointerToRawData + size - 1;
  });

export const createPeRelocationDiscovery = (
  reader: FileRangeReader, core: PeWindowsCore, relocations: PeBaseRelocationResult | null
): PeRelocationDiscovery | null => {
  const architecture = getPeNativeAotArchitecture(core);
  if (!architecture || !relocations || relocations.warnings?.length ||
      (core.coff.Characteristics & COFF_FILE_CHARACTERISTICS.RELOCS_STRIPPED) !== 0 ||
      core.opt.SizeOfImage > PE_RVA_EXCLUSIVE_LIMIT) return null;
  const sites = collectPeItaniumRelocationSites(relocations, architecture.pointerSize);
  const itaniumImage = createPeItaniumImage(reader, core, architecture.pointerSize);
  // Ambiguous/overlapping layouts retain the independent analyzers' mapping rules.
  if (!sites?.length || !itaniumImage || !hasSharedMapping(reader, core)) return null;
  const nativeImage = createPeNativeAotImage(reader, core,
    architecture.pointerSize, architecture.relocationType);
  const msvcImage = architecture.pointerSize === 8
    ? createMsvcRttiImage(reader, core.sections, core.opt.ImageBase, core.opt.SizeOfImage) : null;
  return { reader, nativeImage, msvcImage, itaniumImage,
    sites: sites.sort((left, right) => itaniumImage.readOrder(left) - itaniumImage.readOrder(right)),
    nativeSites: indexPeNativeAotPointerSites(relocations, nativeImage) ?? new Set(),
    msvcSites: msvcImage ? indexMsvcRttiDir64Sites(relocations, msvcImage) ?? new Set() : new Set(),
    nativeCandidates: new Map(), msvcCandidates: [], boundarySites: [] };
};
