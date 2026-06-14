"use strict";

import { toHex32 } from "../../../binary-utils.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import { isRvaRangeInsideSizeOfImage } from "../layout/rva-limits.js";
import { readMappedNullTerminatedAsciiString } from "../strings/mapped-ascii-string.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";
import {
  type PeDelayImportFunction,
  type ReadDelayThunkFunctions,
  readDelayThunkFunctions32,
  readDelayThunkFunctions64
} from "./delay-thunk-table.js";

const IMAGE_DELAYLOAD_DESCRIPTOR_SIZE = 32; // Microsoft PE format: IMAGE_DELAYLOAD_DESCRIPTOR is eight DWORDs.
// MSVC delayimp.h: dlattrRva marks VC7+ descriptors whose fields are RVAs instead of pointers.
// https://learn.microsoft.com/en-us/cpp/build/reference/understanding-the-helper-function
const DELAY_IMPORT_ATTRIBUTE_DLATTR_RVA = 0x1;
interface DelayImportImageMapping {
  sizeOfImage: number;
}

type DelayImportReadState = {
  reader: FileRangeReader;
  rvaToOff: RvaToOffset;
  readDelayThunkFunctions: ReadDelayThunkFunctions;
  warnings: Set<string>;
};

type DelayImportDescriptor = Omit<PeDelayImportEntry, "name" | "functions"> & {
  DllNameRVA: number;
  allZero: boolean;
};

const readDelayImportName = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  nameRva: number,
  warnings: Set<string>
): Promise<string> => {
  const result = await readMappedNullTerminatedAsciiString(
    reader,
    reader.size,
    rvaToOff,
    nameRva >>> 0,
    reader.size
  );
  if (!result) {
    warnings.add("Delay import name RVA does not map to file data.");
    return "";
  }
  if (!result.terminated) warnings.add("Delay import name string truncated.");
  return result.text;
};

const validateDelayImportDirectory = (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  mapping?: DelayImportImageMapping
): { dir: PeDataDirectory; base: number } | { result: { entries: PeDelayImportEntry[]; warning?: string } | null } => {
  const dir = dataDirs.find(d => d.name === "DELAY_IMPORT");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return { result: null };
  if (dir.rva === 0) {
    return { result: { entries: [], warning: "Delay import directory has a non-zero size but RVA is 0." } };
  }
  if (dir.size === 0) {
    return { result: { entries: [], warning: "Delay import directory has an RVA but size is 0." } };
  }
  const base = rvaToOff(dir.rva);
  if (base == null) {
    if (mapping && isRvaRangeInsideSizeOfImage(dir.rva, dir.size, mapping.sizeOfImage)) {
      return { result: { entries: [] } };
    }
    if (mapping) return { result: { entries: [], warning: "Delay import directory range is outside SizeOfImage." } };
    return { result: { entries: [], warning: "Delay import directory RVA does not map to file data." } };
  }
  if (base < 0 || base >= reader.size) {
    return { result: { entries: [], warning: "Delay import directory starts outside file data." } };
  }
  return { dir, base };
};

export interface PeDelayImportEntry {
  name: string;
  Attributes: number;
  ModuleHandleRVA: number;
  ImportAddressTableRVA: number;
  ImportNameTableRVA: number;
  BoundImportAddressTableRVA: number;
  UnloadInformationTableRVA: number;
  TimeDateStamp: number;
  functions: PeDelayImportFunction[];
}

const readDelayImportDescriptor = async (
  reader: FileRangeReader,
  descriptorOff: number,
  descriptorSize: number
): Promise<DelayImportDescriptor | null> => {
  const dv = await reader.read(descriptorOff, descriptorSize);
  if (dv.byteLength < IMAGE_DELAYLOAD_DESCRIPTOR_SIZE) return null;
  const Attributes = dv.getUint32(0, true);
  const DllNameRVA = dv.getUint32(4, true);
  const ModuleHandleRVA = dv.getUint32(8, true);
  const ImportAddressTableRVA = dv.getUint32(12, true);
  const ImportNameTableRVA = dv.getUint32(16, true);
  const BoundImportAddressTableRVA = dv.getUint32(20, true);
  const UnloadInformationTableRVA = dv.getUint32(24, true);
  const TimeDateStamp = dv.getUint32(28, true);
  return {
    Attributes,
    DllNameRVA,
    ModuleHandleRVA,
    ImportAddressTableRVA,
    ImportNameTableRVA,
    BoundImportAddressTableRVA,
    UnloadInformationTableRVA,
    TimeDateStamp,
    allZero: !Attributes && !DllNameRVA && !ModuleHandleRVA && !ImportAddressTableRVA &&
      !ImportNameTableRVA && !BoundImportAddressTableRVA && !UnloadInformationTableRVA && !TimeDateStamp
  };
};

const readDelayImportFunctions = async (
  state: DelayImportReadState,
  descriptor: DelayImportDescriptor
): Promise<{ functions: PeDelayImportFunction[]; terminated: boolean }> => {
  const intRva = descriptor.ImportNameTableRVA >>> 0;
  const intOff = intRva ? state.rvaToOff(intRva) : null;
  if (!intRva) return { functions: [], terminated: true };
  if (intOff == null) {
    state.warnings.add("Delay Import Name Table RVA does not map to file data.");
    return { functions: [], terminated: false };
  }
  const maxThunkEntries = (entrySize: number): number => Math.floor(state.reader.size / entrySize) + 1;
  const thunkTable = await state.readDelayThunkFunctions(
    state.reader,
    state.rvaToOff,
    intRva,
    state.warnings,
    maxThunkEntries
  );
  if (!thunkTable.terminated) state.warnings.add("Delay-load thunk table is not terminated by a null entry.");
  return thunkTable;
};

const collectDelayImportDescriptorWarnings = (
  warnings: Set<string>,
  descriptor: DelayImportDescriptor
): void => {
  const unknownAttributeBits = (descriptor.Attributes >>> 0) & ~DELAY_IMPORT_ATTRIBUTE_DLATTR_RVA;
  if (unknownAttributeBits !== 0) {
    warnings.add(`Delay import descriptor sets unknown Attributes bits (${toHex32(unknownAttributeBits, 8)}).`);
  }
  if (!descriptor.DllNameRVA) warnings.add("Delay import descriptor is missing the DLL name RVA.");
};

const parseDelayImportsWithThunkReader = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  readDelayThunkFunctions: ReadDelayThunkFunctions,
  mapping?: DelayImportImageMapping
): Promise<{ entries: PeDelayImportEntry[]; warning?: string } | null> => {
  const validation = validateDelayImportDirectory(reader, dataDirs, rvaToOff, mapping);
  if ("result" in validation) return validation.result;
  const { dir, base } = validation;
  const availableDirSize = Math.max(0, Math.min(dir.size, Math.max(0, reader.size - base)));
  const entries: PeDelayImportEntry[] = [];
  const warnings = new Set<string>();
  const state = { reader, rvaToOff, readDelayThunkFunctions, warnings };
  if (dir.size < IMAGE_DELAYLOAD_DESCRIPTOR_SIZE || availableDirSize < IMAGE_DELAYLOAD_DESCRIPTOR_SIZE) {
    warnings.add("Delay import directory is smaller than one descriptor; file may be truncated.");
    return { entries, warning: Array.from(warnings).join(" | ") };
  }
  const maxDescriptors = Math.ceil(dir.size / IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  let descriptorTableTerminated = false;
  let descriptorScanStopped = false;
  for (let index = 0; index < maxDescriptors; index += 1) {
    const descriptorRva = (dir.rva + index * IMAGE_DELAYLOAD_DESCRIPTOR_SIZE) >>> 0;
    const descriptorOff = rvaToOff(descriptorRva);
    const remaining = dir.size - index * IMAGE_DELAYLOAD_DESCRIPTOR_SIZE;
    if (descriptorOff == null || descriptorOff < 0) {
      warnings.add("Delay import descriptor RVA does not map to file data.");
      descriptorScanStopped = true;
      break;
    }
    if (remaining <= 0) break;
    const descriptorSize = Math.min(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE, remaining);
    const descriptor = await readDelayImportDescriptor(reader, descriptorOff, descriptorSize);
    if (!descriptor) {
      warnings.add("Delay import descriptor truncated.");
      descriptorScanStopped = true;
      break;
    }
    if (descriptor.allZero) {
      descriptorTableTerminated = true;
      break;
    }
    collectDelayImportDescriptorWarnings(warnings, descriptor);
    if (!descriptor.DllNameRVA) {
      continue;
    }
    const nameOff = rvaToOff(descriptor.DllNameRVA);
    if (descriptor.DllNameRVA && nameOff == null) warnings.add("Delay import name RVA does not map to file data.");
    const thunkTable = await readDelayImportFunctions(state, descriptor);
    entries.push({
      name:
        nameOff != null
          ? await readDelayImportName(reader, rvaToOff, descriptor.DllNameRVA, warnings)
          : "",
      Attributes: descriptor.Attributes,
      ModuleHandleRVA: descriptor.ModuleHandleRVA,
      ImportAddressTableRVA: descriptor.ImportAddressTableRVA,
      ImportNameTableRVA: descriptor.ImportNameTableRVA,
      BoundImportAddressTableRVA: descriptor.BoundImportAddressTableRVA,
      UnloadInformationTableRVA: descriptor.UnloadInformationTableRVA,
      TimeDateStamp: descriptor.TimeDateStamp,
      functions: thunkTable.functions
    });
  }
  if (!descriptorTableTerminated && !descriptorScanStopped) {
    warnings.add(
      "Delay-load import descriptor table is not terminated by an all-zero descriptor within the declared directory size."
    );
  }
  const warning = warnings.size ? Array.from(warnings).join(" | ") : undefined;
  return warning ? { entries, warning } : { entries };
};
export const parseDelayImports32 = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  mapping?: DelayImportImageMapping
): Promise<{ entries: PeDelayImportEntry[]; warning?: string } | null> =>
  parseDelayImportsWithThunkReader(reader, dataDirs, rvaToOff, readDelayThunkFunctions32, mapping);
export const parseDelayImports64 = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  mapping?: DelayImportImageMapping
): Promise<{ entries: PeDelayImportEntry[]; warning?: string } | null> =>
  parseDelayImportsWithThunkReader(reader, dataDirs, rvaToOff, readDelayThunkFunctions64, mapping);
