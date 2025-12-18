"use strict";

import { readLoadConfigPointerRva, type PeLoadConfig } from "./load-config.js";
import type { RvaToOffset } from "./types.js";

export function collectLoadConfigWarnings(
  fileSize: number,
  rvaToOff: RvaToOffset,
  imageBase: number,
  sizeOfImage: number,
  lc: PeLoadConfig
): string[] {
  const warnings: string[] = [];

  const checkTable = (name: string, tableVa: number, count: number, entrySize: number): void => {
    if (!Number.isSafeInteger(count) || count <= 0) return;
    if (!Number.isSafeInteger(entrySize) || entrySize <= 0) return;
    if (!tableVa) {
      warnings.push(`LOAD_CONFIG: ${name} has count ${count} but table pointer is 0.`);
      return;
    }
    const tableRva = readLoadConfigPointerRva(imageBase, tableVa);
    if (tableRva == null) {
      warnings.push(`LOAD_CONFIG: ${name} pointer 0x${tableVa.toString(16)} is not a valid RVA/VA.`);
      return;
    }
    if (Number.isFinite(sizeOfImage) && sizeOfImage > 0 && tableRva < sizeOfImage) {
      const maxImage = Math.floor((sizeOfImage - tableRva) / entrySize);
      if (count > maxImage) warnings.push(`LOAD_CONFIG: ${name} spills past SizeOfImage (${count} > ${maxImage}).`);
    }
    if (!Number.isFinite(fileSize) || fileSize <= 0) return;
    const off = rvaToOff(tableRva);
    if (off == null || off < 0 || off >= fileSize) {
      warnings.push(`LOAD_CONFIG: ${name} RVA 0x${tableRva.toString(16)} does not map to file data.`);
      return;
    }
    const maxFile = Math.floor((fileSize - off) / entrySize);
    if (count > maxFile) warnings.push(`LOAD_CONFIG: ${name} spills past EOF (${count} > ${maxFile}).`);
  };

  checkTable("SEHandlerTable", lc.SEHandlerTable, lc.SEHandlerCount, 4);
  checkTable("GuardCFFunctionTable", lc.GuardCFFunctionTable, lc.GuardCFFunctionCount, 8);
  checkTable(
    "GuardAddressTakenIatEntryTable",
    lc.GuardAddressTakenIatEntryTable,
    lc.GuardAddressTakenIatEntryCount,
    4
  );
  checkTable("GuardLongJumpTargetTable", lc.GuardLongJumpTargetTable, lc.GuardLongJumpTargetCount, 4);
  checkTable("GuardEHContinuationTable", lc.GuardEHContinuationTable, lc.GuardEHContinuationCount, 4);

  return warnings;
}

