"use strict";

import { readLoadConfigPointerRva, type PeLoadConfig } from "./load-config.js";
import { getCfgTargetTableEntrySize } from "./load-config-tables.js";
import type { RvaToOffset } from "./types.js";

export function collectLoadConfigWarnings(
  fileSize: number,
  rvaToOff: RvaToOffset,
  imageBase: number,
  sizeOfImage: number,
  lc: PeLoadConfig
): string[] {
  const warnings: string[] = [];
  const cfgEntrySize = getCfgTargetTableEntrySize(lc.GuardFlags);

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

  const checkPointer = (name: string, pointerVa: number): void => {
    if (!pointerVa) return;
    const rva = readLoadConfigPointerRva(imageBase, pointerVa);
    if (rva == null) {
      warnings.push(`LOAD_CONFIG: ${name} pointer 0x${pointerVa.toString(16)} is not a valid RVA/VA.`);
      return;
    }
    if (Number.isFinite(sizeOfImage) && sizeOfImage > 0 && rva >= sizeOfImage) {
      warnings.push(`LOAD_CONFIG: ${name} RVA 0x${rva.toString(16)} is outside SizeOfImage.`);
      return;
    }
    if (!Number.isFinite(fileSize) || fileSize <= 0) return;
    const off = rvaToOff(rva);
    if (off == null || off < 0 || off >= fileSize) {
      warnings.push(`LOAD_CONFIG: ${name} RVA 0x${rva.toString(16)} does not map to file data.`);
    }
  };

  checkTable("SEHandlerTable", lc.SEHandlerTable, lc.SEHandlerCount, 4);
  checkTable("GuardCFFunctionTable", lc.GuardCFFunctionTable, lc.GuardCFFunctionCount, cfgEntrySize);
  checkTable(
    "GuardAddressTakenIatEntryTable",
    lc.GuardAddressTakenIatEntryTable,
    lc.GuardAddressTakenIatEntryCount,
    cfgEntrySize
  );
  checkTable("GuardLongJumpTargetTable", lc.GuardLongJumpTargetTable, lc.GuardLongJumpTargetCount, cfgEntrySize);
  checkTable("GuardEHContinuationTable", lc.GuardEHContinuationTable, lc.GuardEHContinuationCount, cfgEntrySize);

  checkPointer("LockPrefixTable", lc.LockPrefixTable);
  checkPointer("EditList", lc.EditList);
  checkPointer("SecurityCookie", lc.SecurityCookie);
  checkPointer("GuardCFCheckFunctionPointer", lc.GuardCFCheckFunctionPointer);
  checkPointer("GuardCFDispatchFunctionPointer", lc.GuardCFDispatchFunctionPointer);
  checkPointer("GuardRFFailureRoutine", lc.GuardRFFailureRoutine);
  checkPointer("GuardRFFailureRoutineFunctionPointer", lc.GuardRFFailureRoutineFunctionPointer);
  checkPointer("GuardRFVerifyStackPointerFunctionPointer", lc.GuardRFVerifyStackPointerFunctionPointer);
  checkPointer("GuardXFGCheckFunctionPointer", lc.GuardXFGCheckFunctionPointer);
  checkPointer("GuardXFGDispatchFunctionPointer", lc.GuardXFGDispatchFunctionPointer);
  checkPointer("GuardXFGTableDispatchFunctionPointer", lc.GuardXFGTableDispatchFunctionPointer);
  checkPointer("GuardMemcpyFunctionPointer", lc.GuardMemcpyFunctionPointer);
  checkPointer("CHPEMetadataPointer", lc.CHPEMetadataPointer);
  checkPointer("EnclaveConfigurationPointer", lc.EnclaveConfigurationPointer);
  checkPointer("VolatileMetadataPointer", lc.VolatileMetadataPointer);
  checkPointer("UmaFunctionPointers", lc.UmaFunctionPointers);

  if (lc.DynamicValueRelocTableOffset && !lc.DynamicValueRelocTableSection) {
    warnings.push("LOAD_CONFIG: DynamicValueRelocTableOffset is set but DynamicValueRelocTableSection is 0.");
  }

  return warnings;
}
