"use strict";

import type { PeDynamicRelocations } from "./dynamic-relocations.js";
import {
  buildLoadConfig32,
  buildLoadConfig64,
  type LoadConfigFieldReader
} from "./load-config-layouts.js";
import { createPeLoadConfigResult } from "./load-config-result.js";
import type { AddCoverageRegion, PeDataDirectory, RvaToOffset } from "./types.js";

export type PeLoadConfigCodeIntegrity = {
  Flags: number;
  Catalog: number;
  CatalogOffset: number;
  Reserved: number;
};

export type PeLoadConfigTables = {
  guardFidRvas?: number[];
  guardEhContinuationRvas?: number[];
  guardLongJumpTargetRvas?: number[];
  guardIatRvas?: number[];
  safeSehHandlerRvas?: number[];
};

export interface PeLoadConfig {
  Size: number;
  TimeDateStamp: number;
  Major: number;
  Minor: number;
  GlobalFlagsClear: number;
  GlobalFlagsSet: number;
  CriticalSectionDefaultTimeout: number;
  DeCommitFreeBlockThreshold: number;
  DeCommitTotalFreeThreshold: number;
  LockPrefixTable: number;
  MaximumAllocationSize: number;
  VirtualMemoryThreshold: number;
  ProcessHeapFlags: number;
  ProcessAffinityMask: number;
  CSDVersion: number;
  DependentLoadFlags: number;
  EditList: number;
  SecurityCookie: number;
  SEHandlerTable: number;
  SEHandlerCount: number;
  GuardCFCheckFunctionPointer: number;
  GuardCFDispatchFunctionPointer: number;
  GuardCFFunctionTable: number;
  GuardCFFunctionCount: number;
  CodeIntegrity: PeLoadConfigCodeIntegrity;
  GuardAddressTakenIatEntryTable: number;
  GuardAddressTakenIatEntryCount: number;
  GuardLongJumpTargetTable: number;
  GuardLongJumpTargetCount: number;
  DynamicValueRelocTable: number;
  CHPEMetadataPointer: number;
  GuardRFFailureRoutine: number;
  GuardRFFailureRoutineFunctionPointer: number;
  DynamicValueRelocTableOffset: number;
  DynamicValueRelocTableSection: number;
  Reserved2: number;
  GuardRFVerifyStackPointerFunctionPointer: number;
  HotPatchTableOffset: number;
  Reserved3: number;
  EnclaveConfigurationPointer: number;
  VolatileMetadataPointer: number;
  GuardEHContinuationTable: number;
  GuardEHContinuationCount: number;
  GuardXFGCheckFunctionPointer: number;
  GuardXFGDispatchFunctionPointer: number;
  GuardXFGTableDispatchFunctionPointer: number;
  CastGuardOsDeterminedFailureMode: number;
  GuardMemcpyFunctionPointer: number;
  UmaFunctionPointers: number;
  GuardFlags: number;
  tables?: PeLoadConfigTables;
  dynamicRelocations?: PeDynamicRelocations | null;
  warnings?: string[];
}

const MAX_RVA_BIGINT = 0xffff_ffffn;

const toRvaFromVa = (virtualAddress: number, imageBase: number): number | null => {
  if (!Number.isSafeInteger(virtualAddress) || virtualAddress <= 0) return null;
  if (!Number.isSafeInteger(imageBase) || imageBase < 0) return null;
  const va = BigInt(virtualAddress);
  const base = BigInt(imageBase);
  if (va < base) return null;
  const delta = va - base;
  if (delta > MAX_RVA_BIGINT) return null;
  return Number(delta);
};

const toSafeU64 = (value: bigint): number => {
  const num = Number(value);
  if (!Number.isFinite(num)) return 0;
  try {
    return BigInt(num) === value ? num : 0;
  } catch {
    return 0;
  }
};


const parseLoadConfigDirectoryWithBuilder = async (
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion,
  buildLoadConfig: (reader: LoadConfigFieldReader) => PeLoadConfig
): Promise<PeLoadConfig | null> => {
  const lcDir = dataDirs.find(d => d.name === "LOAD_CONFIG");
  if (!lcDir || (lcDir.rva === 0 && lcDir.size === 0)) return null;
  const warnings: string[] = [];
  if (!lcDir.rva) {
    warnings.push("LOAD_CONFIG has a non-zero size but RVA is 0.");
    return createPeLoadConfigResult(warnings);
  }
  const base = rvaToOff(lcDir.rva);
  if (base == null) {
    warnings.push("LOAD_CONFIG RVA could not be mapped to a file offset.");
    return createPeLoadConfigResult(warnings);
  }
  const fileSize = typeof file.size === "number" ? file.size : Infinity;
  if (base >= fileSize) {
    warnings.push("LOAD_CONFIG starts past end of file.");
    return createPeLoadConfigResult(warnings);
  }
  const availableSize = Math.min(lcDir.size, Math.max(0, fileSize - base));
  if (availableSize < lcDir.size) warnings.push("LOAD_CONFIG directory is truncated by end of file.");
  if (lcDir.size > 0 && lcDir.size < 0x40) {
    warnings.push("LOAD_CONFIG directory is smaller than the minimum documented header size (0x40 bytes).");
  }
  if (availableSize === 0) {
    warnings.push("LOAD_CONFIG does not contain any readable bytes.");
    return createPeLoadConfigResult(warnings);
  }
  addCoverageRegion("LOAD_CONFIG", base, availableSize);
  const view = new DataView(await file.slice(base, base + availableSize).arrayBuffer());
  if (view.byteLength < 4) {
    warnings.push("LOAD_CONFIG is truncated before the Size field.");
    return createPeLoadConfigResult(warnings);
  }
  if (view.byteLength < 12) {
    warnings.push("LOAD_CONFIG is truncated before the fixed header fields are complete.");
  }
  const Size = view.getUint32(0, true);
  const TimeDateStamp = view.byteLength >= 8 ? view.getUint32(4, true) : 0;
  const Major = view.byteLength >= 10 ? view.getUint16(8, true) : 0;
  const Minor = view.byteLength >= 12 ? view.getUint16(10, true) : 0;
  const declaredSize = Number.isFinite(Size) && Size > 0 && Size <= 0x10000 ? Size : 0;
  if (declaredSize > 0 && declaredSize < 0x40) {
    warnings.push("LOAD_CONFIG Size field is smaller than the minimum documented header size (0x40 bytes).");
  }
  if (declaredSize > 0 && availableSize < declaredSize) {
    warnings.push("LOAD_CONFIG bytes available in file are smaller than the Size field.");
  }
  const withinDeclared = (endExclusive: number): boolean => !declaredSize || declaredSize >= endExclusive;
  const has = (offset: number, byteLength: number): boolean =>
    view.byteLength >= offset + byteLength && withinDeclared(offset + byteLength);
  const reader: LoadConfigFieldReader = {
    Size,
    TimeDateStamp,
    Major,
    Minor,
    readU16: (offset: number): number => (has(offset, 2) ? view.getUint16(offset, true) : 0),
    readU32: (offset: number): number => (has(offset, 4) ? view.getUint32(offset, true) : 0),
    readU64: (offset: number): number =>
      (has(offset, 8) ? toSafeU64(view.getBigUint64(offset, true)) : 0)
  };
  const result = buildLoadConfig(reader);
  if (warnings.length) result.warnings = warnings;
  return result;
};

export const parseLoadConfigDirectory32 = async (
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<PeLoadConfig | null> =>
  parseLoadConfigDirectoryWithBuilder(file, dataDirs, rvaToOff, addCoverageRegion, buildLoadConfig32);

export const parseLoadConfigDirectory64 = async (
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<PeLoadConfig | null> =>
  parseLoadConfigDirectoryWithBuilder(file, dataDirs, rvaToOff, addCoverageRegion, buildLoadConfig64);

export function readLoadConfigPointerRva(imageBase: number, pointerVa: number): number | null {
  return toRvaFromVa(pointerVa, imageBase);
}
