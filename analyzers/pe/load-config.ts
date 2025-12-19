"use strict";
import type { PeDynamicRelocations } from "./dynamic-relocations.js";
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
const toRvaFromPointer = (value: number, imageBase: number): number | null => {
  const converted = toRvaFromVa(value, imageBase);
  if (converted != null) return converted;
  if (!Number.isSafeInteger(imageBase) || imageBase < 0) return null;
  if (!Number.isSafeInteger(value) || value <= 0) return null;
  if (value > 0xffff_ffff) return null;
  return value >>> 0;
};
const toSafeU64 = (value: bigint): number => {
  const maxSafeBigInt = BigInt(Number.MAX_SAFE_INTEGER);
  return value <= maxSafeBigInt ? Number(value) : 0;
};
export async function parseLoadConfigDirectory(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion,
  isPlus: boolean
): Promise<PeLoadConfig | null> {
  const lcDir = dataDirs.find(d => d.name === "LOAD_CONFIG");
  if (!lcDir?.rva || lcDir.size < 0x40) return null;
  const base = rvaToOff(lcDir.rva);
  if (base == null) return null;
  const fileSize = typeof file.size === "number" ? file.size : Infinity;
  if (base >= fileSize) return null;
  const availableSize = Math.min(lcDir.size, Math.max(0, fileSize - base));
  addCoverageRegion("LOAD_CONFIG", base, availableSize);
  const view = new DataView(await file.slice(base, base + Math.min(availableSize, 0x200)).arrayBuffer());
  const Size = view.getUint32(0, true);
  const TimeDateStamp = view.getUint32(4, true);
  const Major = view.getUint16(8, true);
  const Minor = view.getUint16(10, true);
  const declaredSize = Number.isFinite(Size) && Size > 0 && Size <= 0x10000 ? Size : 0;
  const withinDeclared = (endExclusive: number): boolean => !declaredSize || declaredSize >= endExclusive;
  const has = (offset: number, byteLength: number): boolean =>
    view.byteLength >= offset + byteLength && withinDeclared(offset + byteLength);
  const readU16 = (offset: number): number => (has(offset, 2) ? view.getUint16(offset, true) : 0);
  const readU32 = (offset: number): number => (has(offset, 4) ? view.getUint32(offset, true) : 0);
  const readU64 = (offset: number): number => (has(offset, 8) ? toSafeU64(view.getBigUint64(offset, true)) : 0);
  const readCount32 = (offset: number): number => readU32(offset);
  const readCount64 = (offset: number): number => readU64(offset);
  const GlobalFlagsClear = readU32(0x0c);
  const GlobalFlagsSet = readU32(0x10);
  const CriticalSectionDefaultTimeout = readU32(0x14);
  const DeCommitFreeBlockThreshold = isPlus ? readU64(0x18) : readU32(0x18);
  const DeCommitTotalFreeThreshold = isPlus ? readU64(0x20) : readU32(0x1c);
  const LockPrefixTable = isPlus ? readU64(0x28) : readU32(0x20);
  const MaximumAllocationSize = isPlus ? readU64(0x30) : readU32(0x24);
  const VirtualMemoryThreshold = isPlus ? readU64(0x38) : readU32(0x28);
  const ProcessHeapFlags = isPlus ? readU32(0x48) : readU32(0x2c);
  const ProcessAffinityMask = isPlus ? readU64(0x40) : readU32(0x30);
  const CSDVersion = isPlus ? readU16(0x4c) : readU16(0x34);
  const DependentLoadFlags = isPlus ? readU16(0x4e) : readU16(0x36);
  const EditList = isPlus ? readU64(0x50) : readU32(0x38);
  const SecurityCookie = isPlus ? readU64(0x58) : readU32(0x3c);
  const SEHandlerTable = isPlus ? readU64(0x60) : readU32(0x40);
  const SEHandlerCount = isPlus ? readCount64(0x68) : readCount32(0x44);
  const GuardCFCheckFunctionPointer = isPlus ? readU64(0x70) : readU32(0x48);
  const GuardCFDispatchFunctionPointer = isPlus ? readU64(0x78) : readU32(0x4c);
  const GuardCFFunctionTable = isPlus ? readU64(0x80) : readU32(0x50);
  const GuardCFFunctionCount = isPlus ? readCount64(0x88) : readCount32(0x54);
  const GuardFlags = isPlus ? readU32(0x90) : readU32(0x58);
  const CodeIntegrityOffset = isPlus ? 0x94 : 0x5c;
  const CodeIntegrity = {
    Flags: readU16(CodeIntegrityOffset),
    Catalog: readU16(CodeIntegrityOffset + 2),
    CatalogOffset: readU32(CodeIntegrityOffset + 4),
    Reserved: readU32(CodeIntegrityOffset + 8)
  };
  const GuardAddressTakenIatEntryTable = isPlus ? readU64(0xa0) : readU32(0x68);
  const GuardAddressTakenIatEntryCount = isPlus ? readCount64(0xa8) : readCount32(0x6c);
  const GuardLongJumpTargetTable = isPlus ? readU64(0xb0) : readU32(0x70);
  const GuardLongJumpTargetCount = isPlus ? readCount64(0xb8) : readCount32(0x74);
  const DynamicValueRelocTable = isPlus ? readU64(0xc0) : readU32(0x78);
  const CHPEMetadataPointer = isPlus ? readU64(0xc8) : readU32(0x7c);
  const GuardRFFailureRoutine = isPlus ? readU64(0xd0) : readU32(0x80);
  const GuardRFFailureRoutineFunctionPointer = isPlus ? readU64(0xd8) : readU32(0x84);
  const DynamicValueRelocTableOffset = isPlus ? readU32(0xe0) : readU32(0x88);
  const DynamicValueRelocTableSection = isPlus ? readU16(0xe4) : readU16(0x8c);
  const Reserved2 = isPlus ? readU16(0xe6) : readU16(0x8e);
  const GuardRFVerifyStackPointerFunctionPointer = isPlus ? readU64(0xe8) : readU32(0x90);
  const HotPatchTableOffset = isPlus ? readU32(0xf0) : readU32(0x94);
  const Reserved3 = isPlus ? readU32(0xf4) : readU32(0x98);
  const EnclaveConfigurationPointer = isPlus ? readU64(0xf8) : readU32(0x9c);
  const VolatileMetadataPointer = isPlus ? readU64(0x100) : readU32(0xa0);
  const GuardEHContinuationTable = isPlus ? readU64(0x108) : readU32(0xa4);
  const GuardEHContinuationCount = isPlus ? readCount64(0x110) : readCount32(0xa8);
  const GuardXFGCheckFunctionPointer = isPlus ? readU64(0x118) : readU32(0xac);
  const GuardXFGDispatchFunctionPointer = isPlus ? readU64(0x120) : readU32(0xb0);
  const GuardXFGTableDispatchFunctionPointer = isPlus ? readU64(0x128) : readU32(0xb4);
  const CastGuardOsDeterminedFailureMode = isPlus ? readU64(0x130) : readU32(0xb8);
  const GuardMemcpyFunctionPointer = isPlus ? readU64(0x138) : readU32(0xbc);
  const UmaFunctionPointers = isPlus ? readU64(0x140) : readU32(0xc0);
  return {
    Size,
    TimeDateStamp,
    Major,
    Minor,
    GlobalFlagsClear: GlobalFlagsClear || 0,
    GlobalFlagsSet: GlobalFlagsSet || 0,
    CriticalSectionDefaultTimeout: CriticalSectionDefaultTimeout || 0,
    DeCommitFreeBlockThreshold: DeCommitFreeBlockThreshold || 0,
    DeCommitTotalFreeThreshold: DeCommitTotalFreeThreshold || 0,
    LockPrefixTable: LockPrefixTable || 0,
    MaximumAllocationSize: MaximumAllocationSize || 0,
    VirtualMemoryThreshold: VirtualMemoryThreshold || 0,
    ProcessHeapFlags: ProcessHeapFlags || 0,
    ProcessAffinityMask: ProcessAffinityMask || 0,
    CSDVersion: CSDVersion || 0,
    DependentLoadFlags: DependentLoadFlags || 0,
    EditList: EditList || 0,
    SecurityCookie: SecurityCookie || 0,
    SEHandlerTable: SEHandlerTable || 0,
    SEHandlerCount,
    GuardCFCheckFunctionPointer: GuardCFCheckFunctionPointer || 0,
    GuardCFDispatchFunctionPointer: GuardCFDispatchFunctionPointer || 0,
    GuardCFFunctionTable: GuardCFFunctionTable || 0,
    GuardCFFunctionCount,
    CodeIntegrity,
    GuardAddressTakenIatEntryTable: GuardAddressTakenIatEntryTable || 0,
    GuardAddressTakenIatEntryCount,
    GuardLongJumpTargetTable: GuardLongJumpTargetTable || 0,
    GuardLongJumpTargetCount,
    DynamicValueRelocTable: DynamicValueRelocTable || 0,
    CHPEMetadataPointer: CHPEMetadataPointer || 0,
    GuardRFFailureRoutine: GuardRFFailureRoutine || 0,
    GuardRFFailureRoutineFunctionPointer: GuardRFFailureRoutineFunctionPointer || 0,
    DynamicValueRelocTableOffset: DynamicValueRelocTableOffset || 0,
    DynamicValueRelocTableSection: DynamicValueRelocTableSection || 0,
    Reserved2: Reserved2 || 0,
    GuardRFVerifyStackPointerFunctionPointer: GuardRFVerifyStackPointerFunctionPointer || 0,
    HotPatchTableOffset: HotPatchTableOffset || 0,
    Reserved3: Reserved3 || 0,
    EnclaveConfigurationPointer: EnclaveConfigurationPointer || 0,
    VolatileMetadataPointer: VolatileMetadataPointer || 0,
    GuardEHContinuationTable: GuardEHContinuationTable || 0,
    GuardEHContinuationCount,
    GuardXFGCheckFunctionPointer: GuardXFGCheckFunctionPointer || 0,
    GuardXFGDispatchFunctionPointer: GuardXFGDispatchFunctionPointer || 0,
    GuardXFGTableDispatchFunctionPointer: GuardXFGTableDispatchFunctionPointer || 0,
    CastGuardOsDeterminedFailureMode: CastGuardOsDeterminedFailureMode || 0,
    GuardMemcpyFunctionPointer: GuardMemcpyFunctionPointer || 0,
    UmaFunctionPointers: UmaFunctionPointers || 0,
    GuardFlags
  };
}
export function readLoadConfigPointerRva(imageBase: number, pointerVa: number): number | null {
  return toRvaFromPointer(pointerVa, imageBase);
}
