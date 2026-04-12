"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeClrVTableFixup } from "./types.js";
import type { RvaToOffset } from "../types.js";

const VTABLE_FIXUP_ENTRY_SIZE_BYTES = 8;

export const parseVTableFixups = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  fileSize: number,
  rva: number,
  size: number,
  issues: string[]
): Promise<PeClrVTableFixup[] | null> => {
  if (!rva) {
    if (size !== 0) {
      issues.push("VTableFixups has a non-zero size but RVA is 0.");
    }
    return null;
  }
  if (size === 0) {
    issues.push("VTableFixups has an RVA but size is 0.");
    return null;
  }
  if (size < VTABLE_FIXUP_ENTRY_SIZE_BYTES) {
    issues.push("VTableFixups size is smaller than a single entry (8 bytes).");
    return null;
  }
  const fileOffset = rvaToOff(rva);
  if (fileOffset == null) {
    issues.push("VTableFixups RVA could not be mapped to a file offset.");
    return null;
  }
  if (fileOffset < 0 || fileOffset >= fileSize) {
    issues.push("VTableFixups location is outside the file.");
    return null;
  }
  const availableBytes = Math.min(size, Math.max(0, fileSize - fileOffset));
  const declaredCount = Math.floor(size / VTABLE_FIXUP_ENTRY_SIZE_BYTES);
  const parsedCount = Math.floor(availableBytes / VTABLE_FIXUP_ENTRY_SIZE_BYTES);
  if (size % VTABLE_FIXUP_ENTRY_SIZE_BYTES !== 0) {
    issues.push("VTableFixups size is not a multiple of entry size (8 bytes).");
  }
  if (parsedCount < declaredCount) {
    issues.push("VTableFixups data is truncated; some entries are missing.");
  }
  const entryCount = parsedCount;
  if (entryCount === 0) return null;
  const fixupView = await reader.read(fileOffset, entryCount * VTABLE_FIXUP_ENTRY_SIZE_BYTES);
  const entries: PeClrVTableFixup[] = [];
  for (let index = 0; index < entryCount; index += 1) {
    const entryOffset = index * VTABLE_FIXUP_ENTRY_SIZE_BYTES;
    entries.push({
      RVA: fixupView.getUint32(entryOffset + 0, true) >>> 0,
      Count: fixupView.getUint16(entryOffset + 4, true),
      Type: fixupView.getUint16(entryOffset + 6, true)
    });
  }
  return entries;
};
