"use strict";

import type { PeLoadConfig, PeLoadConfigCodeIntegrity } from "./index.js";

export type LoadConfigFieldReader = {
  Size: number;
  TimeDateStamp: number;
  Major: number;
  Minor: number;
  readU16: (offset: number) => number;
  readU32: (offset: number) => number;
  readU32AsBigInt: (offset: number) => bigint;
  readU64: (offset: number) => bigint;
  readU64Count: (offset: number, fieldName: string) => number;
};

const parseCodeIntegrity = (
  reader: LoadConfigFieldReader,
  offset: number
): PeLoadConfigCodeIntegrity => ({
  Flags: reader.readU16(offset),
  Catalog: reader.readU16(offset + 2),
  CatalogOffset: reader.readU32(offset + 4),
  Reserved: reader.readU32(offset + 8)
});

// Offsets below come from IMAGE_LOAD_CONFIG_DIRECTORY32 / 64 in the PE format and winnt.h.
export const buildLoadConfig32 = (reader: LoadConfigFieldReader): PeLoadConfig => ({
  Size: reader.Size,
  TimeDateStamp: reader.TimeDateStamp,
  Major: reader.Major,
  Minor: reader.Minor,
  GlobalFlagsClear: reader.readU32(0x0c),
  GlobalFlagsSet: reader.readU32(0x10),
  CriticalSectionDefaultTimeout: reader.readU32(0x14),
  DeCommitFreeBlockThreshold: reader.readU32AsBigInt(0x18),
  DeCommitTotalFreeThreshold: reader.readU32AsBigInt(0x1c),
  LockPrefixTable: reader.readU32AsBigInt(0x20),
  MaximumAllocationSize: reader.readU32AsBigInt(0x24),
  VirtualMemoryThreshold: reader.readU32AsBigInt(0x28),
  ProcessHeapFlags: reader.readU32(0x2c),
  ProcessAffinityMask: reader.readU32AsBigInt(0x30),
  CSDVersion: reader.readU16(0x34),
  DependentLoadFlags: reader.readU16(0x36),
  EditList: reader.readU32AsBigInt(0x38),
  SecurityCookie: reader.readU32AsBigInt(0x3c),
  SEHandlerTable: reader.readU32AsBigInt(0x40),
  SEHandlerCount: reader.readU32(0x44),
  GuardCFCheckFunctionPointer: reader.readU32AsBigInt(0x48),
  GuardCFDispatchFunctionPointer: reader.readU32AsBigInt(0x4c),
  GuardCFFunctionTable: reader.readU32AsBigInt(0x50),
  GuardCFFunctionCount: reader.readU32(0x54),
  CodeIntegrity: parseCodeIntegrity(reader, 0x5c),
  GuardAddressTakenIatEntryTable: reader.readU32AsBigInt(0x68),
  GuardAddressTakenIatEntryCount: reader.readU32(0x6c),
  GuardLongJumpTargetTable: reader.readU32AsBigInt(0x70),
  GuardLongJumpTargetCount: reader.readU32(0x74),
  DynamicValueRelocTable: reader.readU32AsBigInt(0x78),
  CHPEMetadataPointer: reader.readU32AsBigInt(0x7c),
  GuardRFFailureRoutine: reader.readU32AsBigInt(0x80),
  GuardRFFailureRoutineFunctionPointer: reader.readU32AsBigInt(0x84),
  DynamicValueRelocTableOffset: reader.readU32(0x88),
  DynamicValueRelocTableSection: reader.readU16(0x8c),
  Reserved2: reader.readU16(0x8e),
  GuardRFVerifyStackPointerFunctionPointer: reader.readU32AsBigInt(0x90),
  HotPatchTableOffset: reader.readU32(0x94),
  Reserved3: reader.readU32(0x98),
  EnclaveConfigurationPointer: reader.readU32AsBigInt(0x9c),
  VolatileMetadataPointer: reader.readU32AsBigInt(0xa0),
  GuardEHContinuationTable: reader.readU32AsBigInt(0xa4),
  GuardEHContinuationCount: reader.readU32(0xa8),
  GuardXFGCheckFunctionPointer: reader.readU32AsBigInt(0xac),
  GuardXFGDispatchFunctionPointer: reader.readU32AsBigInt(0xb0),
  GuardXFGTableDispatchFunctionPointer: reader.readU32AsBigInt(0xb4),
  CastGuardOsDeterminedFailureMode: reader.readU32AsBigInt(0xb8),
  GuardMemcpyFunctionPointer: reader.readU32AsBigInt(0xbc),
  UmaFunctionPointers: reader.readU32AsBigInt(0xc0),
  GuardFlags: reader.readU32(0x58)
});

export const buildLoadConfig64 = (reader: LoadConfigFieldReader): PeLoadConfig => ({
  Size: reader.Size,
  TimeDateStamp: reader.TimeDateStamp,
  Major: reader.Major,
  Minor: reader.Minor,
  GlobalFlagsClear: reader.readU32(0x0c),
  GlobalFlagsSet: reader.readU32(0x10),
  CriticalSectionDefaultTimeout: reader.readU32(0x14),
  DeCommitFreeBlockThreshold: reader.readU64(0x18),
  DeCommitTotalFreeThreshold: reader.readU64(0x20),
  LockPrefixTable: reader.readU64(0x28),
  MaximumAllocationSize: reader.readU64(0x30),
  VirtualMemoryThreshold: reader.readU64(0x38),
  ProcessHeapFlags: reader.readU32(0x48),
  ProcessAffinityMask: reader.readU64(0x40),
  CSDVersion: reader.readU16(0x4c),
  DependentLoadFlags: reader.readU16(0x4e),
  EditList: reader.readU64(0x50),
  SecurityCookie: reader.readU64(0x58),
  SEHandlerTable: reader.readU64(0x60),
  SEHandlerCount: reader.readU64Count(0x68, "SEHandlerCount"),
  GuardCFCheckFunctionPointer: reader.readU64(0x70),
  GuardCFDispatchFunctionPointer: reader.readU64(0x78),
  GuardCFFunctionTable: reader.readU64(0x80),
  GuardCFFunctionCount: reader.readU64Count(0x88, "GuardCFFunctionCount"),
  CodeIntegrity: parseCodeIntegrity(reader, 0x94),
  GuardAddressTakenIatEntryTable: reader.readU64(0xa0),
  GuardAddressTakenIatEntryCount: reader.readU64Count(0xa8, "GuardAddressTakenIatEntryCount"),
  GuardLongJumpTargetTable: reader.readU64(0xb0),
  GuardLongJumpTargetCount: reader.readU64Count(0xb8, "GuardLongJumpTargetCount"),
  DynamicValueRelocTable: reader.readU64(0xc0),
  CHPEMetadataPointer: reader.readU64(0xc8),
  GuardRFFailureRoutine: reader.readU64(0xd0),
  GuardRFFailureRoutineFunctionPointer: reader.readU64(0xd8),
  DynamicValueRelocTableOffset: reader.readU32(0xe0),
  DynamicValueRelocTableSection: reader.readU16(0xe4),
  Reserved2: reader.readU16(0xe6),
  GuardRFVerifyStackPointerFunctionPointer: reader.readU64(0xe8),
  HotPatchTableOffset: reader.readU32(0xf0),
  Reserved3: reader.readU32(0xf4),
  EnclaveConfigurationPointer: reader.readU64(0xf8),
  VolatileMetadataPointer: reader.readU64(0x100),
  GuardEHContinuationTable: reader.readU64(0x108),
  GuardEHContinuationCount: reader.readU64Count(0x110, "GuardEHContinuationCount"),
  GuardXFGCheckFunctionPointer: reader.readU64(0x118),
  GuardXFGDispatchFunctionPointer: reader.readU64(0x120),
  GuardXFGTableDispatchFunctionPointer: reader.readU64(0x128),
  CastGuardOsDeterminedFailureMode: reader.readU64(0x130),
  GuardMemcpyFunctionPointer: reader.readU64(0x138),
  UmaFunctionPointers: reader.readU64(0x140),
  GuardFlags: reader.readU32(0x90)
});
