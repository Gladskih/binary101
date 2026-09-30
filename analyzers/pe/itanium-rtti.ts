import type { FileRangeReader } from "../file-range-reader.js";
import { discoverItaniumRtti } from "../itanium-rtti/discovery.js";
import type { ItaniumRttiAnalysis, ItaniumRttiImage } from "../itanium-rtti/types.js";
import type {
  PeBaseRelocationBlock, PeBaseRelocationEntry, PeBaseRelocationResult
} from "./directories/reloc.js";
import { createPeItaniumImage } from "./itanium-rtti-image.js";
import type { PeWindowsCore } from "./types.js";

// PE base relocation blocks: 4 KiB page, 8-byte header, WORD entries, DWORD alignment.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only
const isCompleteBlock = (block: PeBaseRelocationBlock): boolean =>
  Number.isSafeInteger(block.pageRva) && block.pageRva >= 0 &&
  block.pageRva < 0x1_0000_0000 && block.pageRva % 4096 === 0 &&
  block.size % 4 === 0 && block.size === 8 + block.entries.length * 2 &&
  block.count === block.entries.length;

const isPointerFixup = (entry: PeBaseRelocationEntry, width: 4 | 8): boolean =>
  entry.type === (width === 8 ? 10 : 3) && Number.isInteger(entry.offset) &&
  entry.offset >= 0 && entry.offset < 4096;

// PE/COFF machine and optional header combinations; no architecture guessing.
const pointerWidth = (core: PeWindowsCore): 4 | 8 | null => {
  if (core.coff.Machine === 0x8664 && core.opt.Magic === 0x20b) return 8;
  return core.coff.Machine === 0x14c && core.opt.Magic === 0x10b ? 4 : null;
};

const relocationSites = (
  relocations: PeBaseRelocationResult, width: 4 | 8
): number[] | null => {
  const sites: number[] = [];
  let count = 0;
  for (const block of relocations.blocks) {
    if (!isCompleteBlock(block)) return null;
    count += block.entries.length;
    for (const entry of block.entries) {
      if (entry.type === 0) continue;
      // Restrict evidence to HIGHLOW on PE32 or DIR64 on PE32+.
      if (!isPointerFixup(entry, width)) return null;
      sites.push(block.pageRva + entry.offset);
    }
  }
  sites.sort((left, right) => left - right);
  if (count !== relocations.totalEntries || sites.some((site, index) =>
    index > 0 && site < sites[index - 1]! + width)) return null;
  return sites;
};

const indexPointers = async (
  image: ItaniumRttiImage, sites: number[], core: PeWindowsCore
): Promise<void> => {
  // RVA order need not match physical section order.
  for (const site of sites.sort((left, right) => image.readOrder(left) - image.readOrder(right))) {
    image.relocations.add(site);
    if (site % image.pointerSize !== 0) continue;
    const view = await image.read(site, image.pointerSize);
    if (view.byteLength !== image.pointerSize) continue;
    const value = image.pointerSize === 8
      ? view.getBigUint64(0, true) : BigInt(view.getUint32(0, true));
    const target = value - core.opt.ImageBase;
    if (target < 0n || target >= BigInt(core.opt.SizeOfImage)) continue;
    image.pointers.set(site, Number(target));
  }
};

const readAnalysis = async (
  reader: FileRangeReader, core: PeWindowsCore,
  relocations: PeBaseRelocationResult, width: 4 | 8
): Promise<ItaniumRttiAnalysis | null> => {
  const sites = relocationSites(relocations, width);
  const image = createPeItaniumImage(reader, core, width);
  if (!sites?.length || !image) return null;
  try {
    await indexPointers(image, sites, core);
    return await discoverItaniumRtti(image);
  } catch {
    return { types: [], warnings: ["Itanium RTTI analysis could not read file data."] };
  }
};

export const analyzePeItaniumRtti = async (
  reader: FileRangeReader, core: PeWindowsCore, relocations: PeBaseRelocationResult | null
): Promise<ItaniumRttiAnalysis | null> => {
  const width = pointerWidth(core);
  if (!width || (core.coff.Characteristics & 1) !== 0) return null;
  if (!relocations || relocations.warnings?.length) return null;
  // Resource policy: limit pointer-index memory and candidate work on hostile input.
  if (relocations.totalEntries > 250_000) return {
    types: [], warnings: ["Itanium RTTI relocation limit reached; analysis skipped."]
  };
  return readAnalysis(reader, core, relocations, width);
};
