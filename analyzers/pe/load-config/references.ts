"use strict";

import {
  DEFAULT_FILE_READ_WINDOW_BYTES,
  type FileRangeReader
} from "../../file-range-reader.js";
import type { PeSection, RvaToOffset } from "../types.js";
import { parseChpeMetadata } from "./chpe.js";
import { parseEnclaveConfiguration } from "./enclave.js";
import { parseHotPatchInfo } from "./hot-patch.js";
import {
  addReferenceMessage,
  createPeRvaMapping,
  readMappedReferenceView,
  readReferencePointer,
  readReferencePointerValue,
  referencePointerRva,
  type PePointerBytes,
  type PeRvaMapping
} from "./reference-reader.js";
import type {
  PeLoadConfigOpaqueReference,
  PeLoadConfigPointerList,
  PeLoadConfigReferences
} from "./reference-types.js";
import type { PeLoadConfig } from "./index.js";
import { parseVolatileMetadata } from "./volatile-metadata.js";

// These fields point at writable image slots whose current pointer-sized values
// are useful independently of the functions to which the loader binds them.
// LLVM lld creates the corresponding __guard_*_fptr symbols as addressable slots.
// https://github.com/llvm/llvm-project/blob/main/lld/COFF/Writer.cpp
const POINTER_SLOT_NAMES = [
  "GuardCFCheckFunctionPointer",
  "GuardCFDispatchFunctionPointer",
  "GuardRFFailureRoutineFunctionPointer",
  "GuardRFVerifyStackPointerFunctionPointer",
  "GuardXFGCheckFunctionPointer",
  "GuardXFGDispatchFunctionPointer",
  "GuardXFGTableDispatchFunctionPointer",
  "CastGuardOsDeterminedFailureMode",
  "GuardMemcpyFunctionPointer"
] as const;

type PointerSpanScan = Readonly<{
  values: bigint[];
  status: "exhausted" | "terminated" | "truncated";
}>;

const scanRawPointerSpan = async (
  reader: FileRangeReader,
  rawOffset: number,
  byteLength: number,
  pointerBytes: PePointerBytes
): Promise<PointerSpanScan> => {
  const values: bigint[] = [];
  for (let consumed = 0; consumed < byteLength;) {
    const chunkBytes = Math.min(DEFAULT_FILE_READ_WINDOW_BYTES, byteLength - consumed);
    const view = await reader.read(rawOffset + consumed, chunkBytes);
    if (view.byteLength < chunkBytes) return { values, status: "truncated" };
    for (let offset = 0; offset < view.byteLength; offset += pointerBytes) {
      const value = readReferencePointer(
        new DataView(view.buffer, view.byteOffset + offset, pointerBytes), pointerBytes
      );
      if (value === 0n) return { values, status: "terminated" };
      values.push(value);
    }
    consumed += view.byteLength;
  }
  return { values, status: "exhausted" };
};

const readLockPrefixTable = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  imageBase: bigint,
  pointerBytes: PePointerBytes,
  warnings: string[],
  notes: string[],
  pointerVa: bigint
): Promise<PeLoadConfigPointerList | null> => {
  const tableRva = referencePointerRva(imageBase, warnings, "LockPrefixTable", pointerVa);
  if (tableRva == null) return null;
  const span = mapping.rawSpan(tableRva);
  if (!span) {
    addReferenceMessage(notes,
      `LOAD_CONFIG: LockPrefixTable RVA 0x${tableRva.toString(16)} is not backed by raw file data.`);
    return null;
  }
  const values: bigint[] = [];
  let cursorRva = tableRva;
  let currentSpan: ReturnType<PeRvaMapping["rawSpan"]> = span;
  while (currentSpan) {
    const alignedBytes = currentSpan[1] - (currentSpan[1] % pointerBytes);
    const result = await scanRawPointerSpan(reader, currentSpan[0], alignedBytes, pointerBytes);
    values.push(...result.values);
    if (result.status === "truncated") {
      addReferenceMessage(warnings, "LOAD_CONFIG: LockPrefixTable is truncated.");
      return { tableRva, values, terminated: false };
    }
    if (result.status === "terminated") return { tableRva, values, terminated: true };
    cursorRva += alignedBytes;
    if (alignedBytes < currentSpan[1]) {
      const crossingView = await readMappedReferenceView(
        reader, mapping, warnings, notes, "LockPrefixTable entry", cursorRva, pointerBytes
      );
      if (!crossingView) return { tableRva, values, terminated: false };
      const crossingValue = readReferencePointer(crossingView, pointerBytes);
      if (crossingValue === 0n) return { tableRva, values, terminated: true };
      values.push(crossingValue);
      cursorRva += pointerBytes;
    }
    currentSpan = mapping.rawSpan(cursorRva);
  }
  addReferenceMessage(warnings,
    "LOAD_CONFIG: LockPrefixTable reaches the end of its raw-mapped region without a terminator.");
  return { tableRva, values, terminated: false };
};

// Microsoft documents EditList as system-reserved and does not publish a target
// layout for UmaFunctionPointers. Keep their values visible without guessing.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory64
const collectOpaqueReferences = (loadConfig: PeLoadConfig): PeLoadConfigOpaqueReference[] => [
  ...(loadConfig.EditList === 0n ? [] : [{
    name: "EditList" as const,
    pointerVa: loadConfig.EditList,
    reason: "Reserved for use by the system; no target layout is published."
  }]),
  ...(loadConfig.UmaFunctionPointers === 0n ? [] : [{
    name: "UmaFunctionPointers" as const,
    pointerVa: loadConfig.UmaFunctionPointers,
    reason: "No table layout, element count, or terminator is published."
  }])
];

const readPointerSlots = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  imageBase: bigint,
  pointerBytes: PePointerBytes,
  warnings: string[],
  notes: string[],
  loadConfig: PeLoadConfig
): Promise<PeLoadConfigReferences["pointerSlots"]> => Object.fromEntries(
  (await Promise.all(POINTER_SLOT_NAMES.map(async name => {
    const value = await readReferencePointerValue(
      reader, mapping, imageBase, pointerBytes, warnings, notes, name, loadConfig[name]
    );
    return value ? [name, value] as const : null;
  }))).filter(entry => entry != null)
);

const collectStructuredReferences = (
  lockPrefixTable: PeLoadConfigReferences["lockPrefixTable"] | null,
  securityCookie: PeLoadConfigReferences["securityCookie"] | null,
  pointerSlots: PeLoadConfigReferences["pointerSlots"],
  chpeMetadata: PeLoadConfigReferences["chpeMetadata"] | null,
  enclaveConfiguration: PeLoadConfigReferences["enclaveConfiguration"] | null,
  hotPatch: PeLoadConfigReferences["hotPatch"] | null,
  volatileMetadata: PeLoadConfigReferences["volatileMetadata"] | null
): PeLoadConfigReferences => ({
  ...(lockPrefixTable ? { lockPrefixTable } : {}),
  ...(securityCookie ? { securityCookie } : {}),
  ...(pointerSlots && Object.keys(pointerSlots).length ? { pointerSlots } : {}),
  ...(chpeMetadata ? { chpeMetadata } : {}),
  ...(enclaveConfiguration ? { enclaveConfiguration } : {}),
  ...(hotPatch ? { hotPatch } : {}),
  ...(volatileMetadata ? { volatileMetadata } : {})
});

export const parseLoadConfigReferences = async (
  reader: FileRangeReader,
  sections: PeSection[],
  sizeOfHeaders: number,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  pointerBytes: PePointerBytes,
  loadConfig: PeLoadConfig
): Promise<PeLoadConfigReferences> => {
  const warnings: string[] = [];
  const notes: string[] = [];
  const mapping = createPeRvaMapping(reader.size, sections, sizeOfHeaders, rvaToOff);
  const pointerSlots = await readPointerSlots(
    reader, mapping, imageBase, pointerBytes, warnings, notes, loadConfig
  );
  const lockPrefixTable = await readLockPrefixTable(
    reader, mapping, imageBase, pointerBytes,
    warnings, notes, loadConfig.LockPrefixTable
  );
  const securityCookie = await readReferencePointerValue(
    reader, mapping, imageBase, pointerBytes, warnings, notes,
    "SecurityCookie", loadConfig.SecurityCookie
  );
  const chpeMetadata = await parseChpeMetadata(
    reader, mapping, imageBase, pointerBytes, warnings, notes, loadConfig.CHPEMetadataPointer
  );
  const enclaveConfiguration = await parseEnclaveConfiguration(
    reader, mapping, imageBase, pointerBytes,
    warnings, notes, loadConfig.EnclaveConfigurationPointer
  );
  const hotPatch = loadConfig.HotPatchTableOffset === 0 ? null : await parseHotPatchInfo(
    reader, mapping, warnings, notes, loadConfig.HotPatchTableOffset
  );
  const volatileMetadata = await parseVolatileMetadata(
    reader, mapping, imageBase, warnings, notes, loadConfig.VolatileMetadataPointer
  );
  const opaque = collectOpaqueReferences(loadConfig);
  const structured = collectStructuredReferences(
    lockPrefixTable, securityCookie, pointerSlots, chpeMetadata,
    enclaveConfiguration, hotPatch, volatileMetadata
  );
  return {
    ...structured,
    ...(opaque.length ? { opaque } : {}),
    ...(warnings.length ? { warnings } : {}),
    ...(notes.length ? { notes } : {})
  };
};
