"use strict";

import { readLoadConfigPointerRva, type PeLoadConfig } from "./index.js";
import { getCfgTargetTableEntrySize } from "./tables.js";
import type { RvaToOffset } from "../types.js";

export type PeLoadConfigDiagnostics = {
  warnings: string[];
  notes: string[];
};

const formatRvaNote = (name: string, rva: number): string =>
  `LOAD_CONFIG: ${name} RVA 0x${rva.toString(16)} is not backed by raw file data.`;

export function collectLoadConfigDiagnostics(
  fileSize: number,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  sizeOfImage: number,
  lc: PeLoadConfig
): PeLoadConfigDiagnostics {
  const warnings: string[] = [];
  const notes: string[] = [];
  const cfgEntrySize = getCfgTargetTableEntrySize(lc.GuardFlags);

  const checkTable = (name: string, tableVa: bigint, count: number, entrySize: number): void => {
    if (!Number.isSafeInteger(count) || count <= 0) return;
    if (!Number.isSafeInteger(entrySize) || entrySize <= 0) return;
    if (!tableVa) {
      warnings.push(`LOAD_CONFIG: ${name} has count ${count} but table pointer is 0.`);
      return;
    }
    const tableRva = readLoadConfigPointerRva(imageBase, tableVa);
    if (tableRva == null) {
      warnings.push(`LOAD_CONFIG: ${name} pointer 0x${tableVa.toString(16)} is not a valid VA.`);
      return;
    }
    if (Number.isFinite(sizeOfImage) && sizeOfImage > 0) {
      if (tableRva >= sizeOfImage) {
        warnings.push(`LOAD_CONFIG: ${name} RVA 0x${tableRva.toString(16)} is outside SizeOfImage.`);
      } else {
        const maxImage = Math.floor((sizeOfImage - tableRva) / entrySize);
        if (count > maxImage) warnings.push(`LOAD_CONFIG: ${name} spills past SizeOfImage (${count} > ${maxImage}).`);
      }
    }
    if (!Number.isFinite(fileSize) || fileSize <= 0) return;
    const off = rvaToOff(tableRva);
    if (off == null) {
      notes.push(formatRvaNote(name, tableRva));
      return;
    }
    if (off < 0 || off >= fileSize) {
      warnings.push(`LOAD_CONFIG: ${name} RVA 0x${tableRva.toString(16)} maps outside file data.`);
      return;
    }
    const maxFile = Math.floor((fileSize - off) / entrySize);
    if (count > maxFile) warnings.push(`LOAD_CONFIG: ${name} spills past EOF (${count} > ${maxFile}).`);
  };

  const checkPointer = (name: string, pointerVa: bigint): void => {
    if (pointerVa === 0n) return;
    const rva = readLoadConfigPointerRva(imageBase, pointerVa);
    if (rva == null) {
      warnings.push(`LOAD_CONFIG: ${name} pointer 0x${pointerVa.toString(16)} is not a valid VA.`);
      return;
    }
    if (Number.isFinite(sizeOfImage) && sizeOfImage > 0 && rva >= sizeOfImage) {
      warnings.push(`LOAD_CONFIG: ${name} RVA 0x${rva.toString(16)} is outside SizeOfImage.`);
      return;
    }
    if (!Number.isFinite(fileSize) || fileSize <= 0) return;
    const off = rvaToOff(rva);
    if (off == null) {
      notes.push(formatRvaNote(name, rva));
      return;
    }
    if (off < 0 || off >= fileSize) {
      warnings.push(`LOAD_CONFIG: ${name} RVA 0x${rva.toString(16)} maps outside file data.`);
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

  return { warnings, notes };
}
