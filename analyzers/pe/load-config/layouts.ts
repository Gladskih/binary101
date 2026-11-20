"use strict";

import { EH_CONTINUATION_LAYOUT } from "./eh-continuation-layout.js";
import type { PeLoadConfig, PeLoadConfigCodeIntegrity } from "./index.js";

export type LoadConfigFieldReader = {
  Size: number;
  TimeDateStamp: number;
  Major: number;
  Minor: number;
  readU16: (offset: number, fieldName: string) => number;
  readU32: (offset: number, fieldName: string) => number;
  readU32AsBigInt: (offset: number, fieldName: string) => bigint;
  readU64: (offset: number, fieldName: string) => bigint;
  readU64Count: (offset: number, fieldName: string) => number;
};

const parseCodeIntegrity = (
  reader: LoadConfigFieldReader,
  offset: number
): PeLoadConfigCodeIntegrity => ({
  Flags: reader.readU16(offset, "CodeIntegrity.Flags"),
  Catalog: reader.readU16(offset + 2, "CodeIntegrity.Catalog"),
  CatalogOffset: reader.readU32(offset + 4, "CodeIntegrity.CatalogOffset"),
  Reserved: reader.readU32(offset + 8, "CodeIntegrity.Reserved")
});

// Offsets below come from IMAGE_LOAD_CONFIG_DIRECTORY32 / 64 in the PE format and winnt.h.
export const buildLoadConfig32 = (reader: LoadConfigFieldReader): PeLoadConfig => ({
  Size: reader.Size,
  TimeDateStamp: reader.TimeDateStamp,
  Major: reader.Major,
  Minor: reader.Minor,
  GlobalFlagsClear: reader.readU32(0x0c, "GlobalFlagsClear"),
  GlobalFlagsSet: reader.readU32(0x10, "GlobalFlagsSet"),
  CriticalSectionDefaultTimeout: reader.readU32(0x14, "CriticalSectionDefaultTimeout"),
  DeCommitFreeBlockThreshold: reader.readU32AsBigInt(0x18, "DeCommitFreeBlockThreshold"),
  DeCommitTotalFreeThreshold: reader.readU32AsBigInt(0x1c, "DeCommitTotalFreeThreshold"),
  LockPrefixTable: reader.readU32AsBigInt(0x20, "LockPrefixTable"),
  MaximumAllocationSize: reader.readU32AsBigInt(0x24, "MaximumAllocationSize"),
  VirtualMemoryThreshold: reader.readU32AsBigInt(0x28, "VirtualMemoryThreshold"),
  ProcessHeapFlags: reader.readU32(0x2c, "ProcessHeapFlags"),
  ProcessAffinityMask: reader.readU32AsBigInt(0x30, "ProcessAffinityMask"),
  CSDVersion: reader.readU16(0x34, "CSDVersion"),
  DependentLoadFlags: reader.readU16(0x36, "DependentLoadFlags"),
  EditList: reader.readU32AsBigInt(0x38, "EditList"),
  SecurityCookie: reader.readU32AsBigInt(0x3c, "SecurityCookie"),
  SEHandlerTable: reader.readU32AsBigInt(0x40, "SEHandlerTable"),
  SEHandlerCount: reader.readU32(0x44, "SEHandlerCount"),
  GuardCFCheckFunctionPointer: reader.readU32AsBigInt(0x48, "GuardCFCheckFunctionPointer"),
  GuardCFDispatchFunctionPointer: reader.readU32AsBigInt(0x4c, "GuardCFDispatchFunctionPointer"),
  GuardCFFunctionTable: reader.readU32AsBigInt(0x50, "GuardCFFunctionTable"),
  GuardCFFunctionCount: reader.readU32(0x54, "GuardCFFunctionCount"),
  CodeIntegrity: parseCodeIntegrity(reader, 0x5c),
  GuardAddressTakenIatEntryTable: reader.readU32AsBigInt(0x68, "GuardAddressTakenIatEntryTable"),
  GuardAddressTakenIatEntryCount: reader.readU32(0x6c, "GuardAddressTakenIatEntryCount"),
  GuardLongJumpTargetTable: reader.readU32AsBigInt(0x70, "GuardLongJumpTargetTable"),
  GuardLongJumpTargetCount: reader.readU32(0x74, "GuardLongJumpTargetCount"),
  DynamicValueRelocTable: reader.readU32AsBigInt(0x78, "DynamicValueRelocTable"),
  CHPEMetadataPointer: reader.readU32AsBigInt(0x7c, "CHPEMetadataPointer"),
  GuardRFFailureRoutine: reader.readU32AsBigInt(0x80, "GuardRFFailureRoutine"),
  GuardRFFailureRoutineFunctionPointer: reader.readU32AsBigInt(0x84, "GuardRFFailureRoutineFunctionPointer"),
  DynamicValueRelocTableOffset: reader.readU32(0x88, "DynamicValueRelocTableOffset"),
  DynamicValueRelocTableSection: reader.readU16(0x8c, "DynamicValueRelocTableSection"),
  Reserved2: reader.readU16(0x8e, "Reserved2"),
  GuardRFVerifyStackPointerFunctionPointer: reader.readU32AsBigInt(0x90, "GuardRFVerifyStackPointerFunctionPointer"),
  HotPatchTableOffset: reader.readU32(0x94, "HotPatchTableOffset"),
  Reserved3: reader.readU32(0x98, "Reserved3"),
  EnclaveConfigurationPointer: reader.readU32AsBigInt(0x9c, "EnclaveConfigurationPointer"),
  VolatileMetadataPointer: reader.readU32AsBigInt(0xa0, "VolatileMetadataPointer"),
  GuardEHContinuationTable: reader.readU32AsBigInt(EH_CONTINUATION_LAYOUT[4].table, "GuardEHContinuationTable"),
  GuardEHContinuationCount: reader.readU32(EH_CONTINUATION_LAYOUT[4].count, "GuardEHContinuationCount"),
  GuardXFGCheckFunctionPointer: reader.readU32AsBigInt(0xac, "GuardXFGCheckFunctionPointer"),
  GuardXFGDispatchFunctionPointer: reader.readU32AsBigInt(0xb0, "GuardXFGDispatchFunctionPointer"),
  GuardXFGTableDispatchFunctionPointer: reader.readU32AsBigInt(0xb4, "GuardXFGTableDispatchFunctionPointer"),
  CastGuardOsDeterminedFailureMode: reader.readU32AsBigInt(0xb8, "CastGuardOsDeterminedFailureMode"),
  GuardMemcpyFunctionPointer: reader.readU32AsBigInt(0xbc, "GuardMemcpyFunctionPointer"),
  UmaFunctionPointers: reader.readU32AsBigInt(0xc0, "UmaFunctionPointers"),
  GuardFlags: reader.readU32(0x58, "GuardFlags")
});

export const buildLoadConfig64 = (reader: LoadConfigFieldReader): PeLoadConfig => ({
  Size: reader.Size,
  TimeDateStamp: reader.TimeDateStamp,
  Major: reader.Major,
  Minor: reader.Minor,
  GlobalFlagsClear: reader.readU32(0x0c, "GlobalFlagsClear"),
  GlobalFlagsSet: reader.readU32(0x10, "GlobalFlagsSet"),
  CriticalSectionDefaultTimeout: reader.readU32(0x14, "CriticalSectionDefaultTimeout"),
  DeCommitFreeBlockThreshold: reader.readU64(0x18, "DeCommitFreeBlockThreshold"),
  DeCommitTotalFreeThreshold: reader.readU64(0x20, "DeCommitTotalFreeThreshold"),
  LockPrefixTable: reader.readU64(0x28, "LockPrefixTable"),
  MaximumAllocationSize: reader.readU64(0x30, "MaximumAllocationSize"),
  VirtualMemoryThreshold: reader.readU64(0x38, "VirtualMemoryThreshold"),
  ProcessHeapFlags: reader.readU32(0x48, "ProcessHeapFlags"),
  ProcessAffinityMask: reader.readU64(0x40, "ProcessAffinityMask"),
  CSDVersion: reader.readU16(0x4c, "CSDVersion"),
  DependentLoadFlags: reader.readU16(0x4e, "DependentLoadFlags"),
  EditList: reader.readU64(0x50, "EditList"),
  SecurityCookie: reader.readU64(0x58, "SecurityCookie"),
  SEHandlerTable: reader.readU64(0x60, "SEHandlerTable"),
  SEHandlerCount: reader.readU64Count(0x68, "SEHandlerCount"),
  GuardCFCheckFunctionPointer: reader.readU64(0x70, "GuardCFCheckFunctionPointer"),
  GuardCFDispatchFunctionPointer: reader.readU64(0x78, "GuardCFDispatchFunctionPointer"),
  GuardCFFunctionTable: reader.readU64(0x80, "GuardCFFunctionTable"),
  GuardCFFunctionCount: reader.readU64Count(0x88, "GuardCFFunctionCount"),
  CodeIntegrity: parseCodeIntegrity(reader, 0x94),
  GuardAddressTakenIatEntryTable: reader.readU64(0xa0, "GuardAddressTakenIatEntryTable"),
  GuardAddressTakenIatEntryCount: reader.readU64Count(0xa8, "GuardAddressTakenIatEntryCount"),
  GuardLongJumpTargetTable: reader.readU64(0xb0, "GuardLongJumpTargetTable"),
  GuardLongJumpTargetCount: reader.readU64Count(0xb8, "GuardLongJumpTargetCount"),
  DynamicValueRelocTable: reader.readU64(0xc0, "DynamicValueRelocTable"),
  CHPEMetadataPointer: reader.readU64(0xc8, "CHPEMetadataPointer"),
  GuardRFFailureRoutine: reader.readU64(0xd0, "GuardRFFailureRoutine"),
  GuardRFFailureRoutineFunctionPointer: reader.readU64(0xd8, "GuardRFFailureRoutineFunctionPointer"),
  DynamicValueRelocTableOffset: reader.readU32(0xe0, "DynamicValueRelocTableOffset"),
  DynamicValueRelocTableSection: reader.readU16(0xe4, "DynamicValueRelocTableSection"),
  Reserved2: reader.readU16(0xe6, "Reserved2"),
  GuardRFVerifyStackPointerFunctionPointer: reader.readU64(0xe8, "GuardRFVerifyStackPointerFunctionPointer"),
  HotPatchTableOffset: reader.readU32(0xf0, "HotPatchTableOffset"),
  Reserved3: reader.readU32(0xf4, "Reserved3"),
  EnclaveConfigurationPointer: reader.readU64(0xf8, "EnclaveConfigurationPointer"),
  VolatileMetadataPointer: reader.readU64(0x100, "VolatileMetadataPointer"),
  GuardEHContinuationTable: reader.readU64(EH_CONTINUATION_LAYOUT[8].table, "GuardEHContinuationTable"),
  GuardEHContinuationCount: reader.readU64Count(EH_CONTINUATION_LAYOUT[8].count, "GuardEHContinuationCount"),
  GuardXFGCheckFunctionPointer: reader.readU64(0x118, "GuardXFGCheckFunctionPointer"),
  GuardXFGDispatchFunctionPointer: reader.readU64(0x120, "GuardXFGDispatchFunctionPointer"),
  GuardXFGTableDispatchFunctionPointer: reader.readU64(0x128, "GuardXFGTableDispatchFunctionPointer"),
  CastGuardOsDeterminedFailureMode: reader.readU64(0x130, "CastGuardOsDeterminedFailureMode"),
  GuardMemcpyFunctionPointer: reader.readU64(0x138, "GuardMemcpyFunctionPointer"),
  UmaFunctionPointers: reader.readU64(0x140, "UmaFunctionPointers"),
  GuardFlags: reader.readU32(0x90, "GuardFlags")
});
