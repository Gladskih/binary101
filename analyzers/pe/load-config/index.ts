"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeDynamicRelocations } from "../dynamic-relocations/index.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import {
  buildLoadConfig32,
  buildLoadConfig64,
  type LoadConfigFieldReader
} from "./layouts.js";
import { createPeLoadConfigResult } from "./result.js";
import type { PeLoadConfigReferences } from "./reference-types.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";

export type PeLoadConfigCodeIntegrity = {
  Flags: number;
  Catalog: number;
  CatalogOffset: number;
  Reserved: number;
};

export type PeLoadConfigCheckStatus = "pass" | "fail" | "info";

export type PeLoadConfigCheck = {
  status: PeLoadConfigCheckStatus;
  title: string;
  detail: string;
  source?: string;
};

export type PeLoadConfigTableKind =
  | "guardFid"
  | "guardIat"
  | "guardLongJump"
  | "guardEhContinuation"
  | "safeSeh";

export type PeLoadConfigTableEntry = {
  index: number;
  rva: number;
  metadataBytes?: number[];
  gfidsFlags?: string[];
  unknownGfidsFlagBits?: number;
};

export type PeLoadConfigTable = {
  kind: PeLoadConfigTableKind;
  name: string;
  tableVa: bigint;
  tableRva: number | null;
  declaredCount: number;
  entrySize: number;
  entries: PeLoadConfigTableEntry[];
  truncated: boolean;
  notes?: string[];
  warnings?: string[];
};

export type PeLoadConfigTables = {
  guardFid?: PeLoadConfigTable;
  guardEhContinuation?: PeLoadConfigTable;
  guardLongJumpTarget?: PeLoadConfigTable;
  guardIat?: PeLoadConfigTable;
  safeSehHandler?: PeLoadConfigTable;
};

export interface PeLoadConfig {
  Size: number;
  TimeDateStamp: number;
  Major: number;
  Minor: number;
  GlobalFlagsClear: number;
  GlobalFlagsSet: number;
  CriticalSectionDefaultTimeout: number;
  DeCommitFreeBlockThreshold: bigint;
  DeCommitTotalFreeThreshold: bigint;
  LockPrefixTable: bigint;
  MaximumAllocationSize: bigint;
  VirtualMemoryThreshold: bigint;
  ProcessHeapFlags: number;
  ProcessAffinityMask: bigint;
  CSDVersion: number;
  DependentLoadFlags: number;
  EditList: bigint;
  SecurityCookie: bigint;
  SEHandlerTable: bigint;
  SEHandlerCount: number;
  GuardCFCheckFunctionPointer: bigint;
  GuardCFDispatchFunctionPointer: bigint;
  GuardCFFunctionTable: bigint;
  GuardCFFunctionCount: number;
  CodeIntegrity: PeLoadConfigCodeIntegrity;
  GuardAddressTakenIatEntryTable: bigint;
  GuardAddressTakenIatEntryCount: number;
  GuardLongJumpTargetTable: bigint;
  GuardLongJumpTargetCount: number;
  DynamicValueRelocTable: bigint;
  CHPEMetadataPointer: bigint;
  GuardRFFailureRoutine: bigint;
  GuardRFFailureRoutineFunctionPointer: bigint;
  DynamicValueRelocTableOffset: number;
  DynamicValueRelocTableSection: number;
  Reserved2: number;
  GuardRFVerifyStackPointerFunctionPointer: bigint;
  HotPatchTableOffset: number;
  Reserved3: number;
  EnclaveConfigurationPointer: bigint;
  VolatileMetadataPointer: bigint;
  GuardEHContinuationTable: bigint;
  GuardEHContinuationCount: number;
  GuardXFGCheckFunctionPointer: bigint;
  GuardXFGDispatchFunctionPointer: bigint;
  GuardXFGTableDispatchFunctionPointer: bigint;
  CastGuardOsDeterminedFailureMode: bigint;
  GuardMemcpyFunctionPointer: bigint;
  UmaFunctionPointers: bigint;
  GuardFlags: number;
  tables?: PeLoadConfigTables;
  dynamicRelocations?: PeDynamicRelocations | null;
  references?: PeLoadConfigReferences;
  checks?: PeLoadConfigCheck[];
  notes?: string[];
  warnings?: string[];
}

const MAX_RVA_BIGINT = 0xffff_ffffn;

const toRvaFromVa = (virtualAddress: bigint, imageBase: bigint): number | null => {
  if (virtualAddress === 0n || imageBase <= 0n) return null;
  if (virtualAddress < imageBase) return null;
  const delta = virtualAddress - imageBase;
  if (delta > MAX_RVA_BIGINT) return null;
  return Number(delta);
};

const toSafeCount = (fieldName: string, value: bigint, warnings: string[]): number => {
  if (value <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(value);
  warnings.push(
    `LOAD_CONFIG: ${fieldName} exceeds Number.MAX_SAFE_INTEGER and cannot be represented exactly; using 0.`
  );
  return 0;
};

const readLoadConfigBytes = async (
  reader: FileRangeReader,
  directory: PeDataDirectory,
  rvaToOff: RvaToOffset,
  knownSize: number,
  warnings: string[],
  notes: string[]
): Promise<DataView | null> => {
  if (directory.size > 0 && directory.size < 0x40) {
    warnings.push("LOAD_CONFIG directory is smaller than the minimum documented header size (0x40 bytes).");
  }
  if (directory.size === 0) {
    warnings.push("LOAD_CONFIG does not contain any readable bytes.");
    return null;
  }
  const initialView = await readMappedRvaPrefix(
    reader, directory.rva, Math.min(4, directory.size), rvaToOff
  );
  if (initialView.byteLength < 4) {
    warnings.push("LOAD_CONFIG is truncated before the Size field.");
    return null;
  }
  const declaredSize = initialView.getUint32(0, true);
  if (Math.max(directory.size, declaredSize) > knownSize) {
    notes.push(
      `LOAD_CONFIG contains bytes beyond the ${knownSize}-byte layout published by the current Windows SDK.`
    );
  }
  return readMappedRvaPrefix(
    reader, directory.rva, Math.min(Math.max(directory.size, declaredSize), knownSize), rvaToOff
  );
};

const createFieldReader = (view: DataView, warnings: string[]): LoadConfigFieldReader => {
  const declaredSize = view.getUint32(0, true);
  const withinDeclared = (endExclusive: number): boolean => !declaredSize || declaredSize >= endExclusive;
  const has = (offset: number, byteLength: number): boolean =>
    view.byteLength >= offset + byteLength && withinDeclared(offset + byteLength);
  return {
    Size: declaredSize,
    TimeDateStamp: view.byteLength >= 8 ? view.getUint32(4, true) : 0,
    Major: view.byteLength >= 10 ? view.getUint16(8, true) : 0,
    Minor: view.byteLength >= 12 ? view.getUint16(10, true) : 0,
    readU16: offset => (has(offset, 2) ? view.getUint16(offset, true) : 0),
    readU32: offset => (has(offset, 4) ? view.getUint32(offset, true) : 0),
    readU32AsBigInt: offset => (has(offset, 4) ? BigInt(view.getUint32(offset, true)) : 0n),
    readU64: offset => (has(offset, 8) ? view.getBigUint64(offset, true) : 0n),
    readU64Count: (offset, fieldName) =>
      (has(offset, 8) ? toSafeCount(fieldName, view.getBigUint64(offset, true), warnings) : 0)
  };
};

const parseLoadConfigDirectoryWithBuilder = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  buildLoadConfig: (reader: LoadConfigFieldReader) => PeLoadConfig,
  knownSize: number
): Promise<PeLoadConfig | null> => {
  const directory = dataDirs.find(item => item.name === "LOAD_CONFIG");
  if (!directory || (directory.rva === 0 && directory.size === 0)) return null;
  const warnings: string[] = [];
  const notes: string[] = [];
  if (!directory.rva) return createPeLoadConfigResult(["LOAD_CONFIG has a non-zero size but RVA is 0."]);
  const base = rvaToOff(directory.rva);
  if (base == null) return createPeLoadConfigResult(["LOAD_CONFIG RVA could not be mapped to a file offset."]);
  if (base >= reader.size) return createPeLoadConfigResult(["LOAD_CONFIG starts past end of file."]);
  const view = await readLoadConfigBytes(reader, directory, rvaToOff, knownSize, warnings, notes);
  if (!view) return createPeLoadConfigResult(warnings);
  if (view.byteLength < 12) {
    warnings.push("LOAD_CONFIG is truncated before the fixed header fields are complete.");
  }
  const declaredSize = view.getUint32(0, true);
  if (declaredSize > 0 && declaredSize < 0x40) {
    warnings.push("LOAD_CONFIG Size field is smaller than the minimum documented header size (0x40 bytes).");
  }
  if (declaredSize > 0 && view.byteLength < Math.min(declaredSize, knownSize)) {
    warnings.push("LOAD_CONFIG bytes available in file are smaller than the Size field.");
  }
  const result = buildLoadConfig(createFieldReader(view, warnings));
  if (warnings.length) result.warnings = warnings;
  if (notes.length) result.notes = notes;
  return result;
};

export const parseLoadConfigDirectory32 = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<PeLoadConfig | null> =>
  // Windows SDK 10.0.26100.0 IMAGE_LOAD_CONFIG_DIRECTORY32 ends at byte 0xc4.
  parseLoadConfigDirectoryWithBuilder(reader, dataDirs, rvaToOff, buildLoadConfig32, 0xc4);

export const parseLoadConfigDirectory64 = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<PeLoadConfig | null> =>
  // Windows SDK 10.0.26100.0 IMAGE_LOAD_CONFIG_DIRECTORY64 ends at byte 0x148.
  parseLoadConfigDirectoryWithBuilder(reader, dataDirs, rvaToOff, buildLoadConfig64, 0x148);

export function readLoadConfigPointerRva(imageBase: bigint, pointerVa: bigint): number | null {
  return toRvaFromVa(pointerVa, imageBase);
}
