"use strict";

import {
  IMAGE_REL_BASED_DIR64,
  type PeBaseRelocationBlock,
  type PeBaseRelocationResult
} from "../directories/reloc.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import type { MsvcRttiImage } from "./image.js";
import { IMAGE_POINTER_SIZE } from "./layout.js";

const BASE_RELOCATION_PAGE_SIZE = 0x1000;

const isConsistentBlock = (block: PeBaseRelocationBlock): boolean =>
  Number.isSafeInteger(block.pageRva) &&
  block.pageRva >= 0 &&
  block.pageRva < PE_RVA_EXCLUSIVE_LIMIT &&
  block.pageRva % BASE_RELOCATION_PAGE_SIZE === 0 &&
  Number.isSafeInteger(block.size) &&
  block.size >= 8 &&
  block.size % Uint32Array.BYTES_PER_ELEMENT === 0 &&
  block.count === block.entries.length;

const dir64SiteRva = (block: PeBaseRelocationBlock, offset: number): number | null => {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= BASE_RELOCATION_PAGE_SIZE) return null;
  const siteRva = block.pageRva + offset;
  return siteRva < PE_RVA_EXCLUSIVE_LIMIT ? siteRva : null;
};

export const indexMsvcRttiDir64Sites = (
  relocations: PeBaseRelocationResult | null,
  image: MsvcRttiImage
): Set<number> | null => {
  if (!relocations || relocations.warnings?.length) return null;
  if (relocations.blocks.some(block => !isConsistentBlock(block))) return null;
  const entryCount = relocations.blocks.reduce((count, block) => count + block.entries.length, 0);
  if (entryCount !== relocations.totalEntries) return null;
  const sites = new Set<number>();
  for (const block of relocations.blocks) {
    for (const entry of block.entries) {
      if (entry.type !== IMAGE_REL_BASED_DIR64) continue;
      const siteRva = dir64SiteRva(block, entry.offset);
      if (siteRva == null || !image.isDataRange(siteRva, IMAGE_POINTER_SIZE, IMAGE_POINTER_SIZE)) continue;
      sites.add(siteRva);
    }
  }
  return sites.size ? sites : null;
};

