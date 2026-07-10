"use strict";

import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import type { MsvcRttiImage } from "./image.js";
import { IMAGE_POINTER_SIZE, MAX_VFTABLE_SLOTS } from "./layout.js";
import type { MsvcRttiVftable } from "./types.js";

const slotRvaAt = (vftableRva: number, index: number): number | null => {
  const rva = vftableRva + index * IMAGE_POINTER_SIZE;
  return Number.isSafeInteger(rva) && rva < PE_RVA_EXCLUSIVE_LIMIT ? rva : null;
};

export const parseRelocationBackedVftable = async (
  image: MsvcRttiImage,
  dir64Sites: Set<number>,
  locatorSlotRva: number,
  completeObjectLocatorRva: number
): Promise<MsvcRttiVftable | null> => {
  const vftableRva = locatorSlotRva + IMAGE_POINTER_SIZE;
  if (vftableRva >= PE_RVA_EXCLUSIVE_LIMIT || vftableRva % IMAGE_POINTER_SIZE !== 0) return null;
  if (!image.isDataRange(vftableRva, IMAGE_POINTER_SIZE, IMAGE_POINTER_SIZE)) return null;
  const functionTargetRvas: number[] = [];
  for (let index = 0; index < MAX_VFTABLE_SLOTS; index += 1) {
    const slotRva = slotRvaAt(vftableRva, index);
    if (slotRva == null || !dir64Sites.has(slotRva)) break;
    const targetRva = await image.readPreferredVaRva(slotRva);
    if (targetRva == null || !image.isExecutableRva(targetRva)) break;
    functionTargetRvas.push(targetRva);
  }
  return functionTargetRvas.length
    ? { rva: vftableRva, locatorSlotRva, completeObjectLocatorRva, functionTargetRvas }
    : null;
};

