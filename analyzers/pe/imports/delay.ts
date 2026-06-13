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
const parseDelayImportsWithThunkReader = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  readDelayThunkFunctions: ReadDelayThunkFunctions,
  mapping?: DelayImportImageMapping
): Promise<{ entries: PeDelayImportEntry[]; warning?: string } | null> => {
  const dir = dataDirs.find(d => d.name === "DELAY_IMPORT");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return null;
  if (dir.rva === 0) {
    return {
      entries: [],
      warning: "Delay import directory has a non-zero size but RVA is 0."
    };
  }
  if (dir.size === 0) {
    return {
      entries: [],
      warning: "Delay import directory has an RVA but size is 0."
    };
  }
  const base = rvaToOff(dir.rva);
  if (base == null) {
    // Microsoft PE format data-directory entries are RVAs in the loaded image, not file offsets,
    // and packers can populate declared image memory before delay-load helpers use it.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
    if (mapping && isRvaRangeInsideSizeOfImage(dir.rva, dir.size, mapping.sizeOfImage)) {
      return { entries: [] };
    }
    if (mapping) {
      return { entries: [], warning: "Delay import directory range is outside SizeOfImage." };
    }
    return { entries: [], warning: "Delay import directory RVA does not map to file data." };
  }
  if (base < 0 || base >= reader.size) {
    return { entries: [], warning: "Delay import directory starts outside file data." };
  }
  const availableDirSize = Math.max(0, Math.min(dir.size, Math.max(0, reader.size - base)));
  const entries: PeDelayImportEntry[] = [];
  const warnings = new Set<string>();
  if (dir.size < IMAGE_DELAYLOAD_DESCRIPTOR_SIZE || availableDirSize < IMAGE_DELAYLOAD_DESCRIPTOR_SIZE) {
    warnings.add("Delay import directory is smaller than one descriptor; file may be truncated.");
    return { entries, warning: Array.from(warnings).join(" | ") };
  }
  const maxThunkEntries = (entrySize: number): number => Math.floor(reader.size / entrySize) + 1;
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
    const dv = await reader.read(descriptorOff, descriptorSize);
    if (dv.byteLength < IMAGE_DELAYLOAD_DESCRIPTOR_SIZE) {
      warnings.add("Delay import descriptor truncated.");
      descriptorScanStopped = true;
      break;
    }
    const Attributes = dv.getUint32(0, true);
    const DllNameRVA = dv.getUint32(4, true);
    const ModuleHandleRVA = dv.getUint32(8, true);
    const ImportAddressTableRVA = dv.getUint32(12, true);
    const ImportNameTableRVA = dv.getUint32(16, true);
    const BoundImportAddressTableRVA = dv.getUint32(20, true);
    const UnloadInformationTableRVA = dv.getUint32(24, true);
    const TimeDateStamp = dv.getUint32(28, true);
    if (
      !Attributes &&
      !DllNameRVA &&
      !ModuleHandleRVA &&
      !ImportAddressTableRVA &&
      !ImportNameTableRVA &&
      !BoundImportAddressTableRVA &&
      !UnloadInformationTableRVA &&
      !TimeDateStamp
    ) {
      descriptorTableTerminated = true;
      break;
    }
    const unknownAttributeBits = (Attributes >>> 0) & ~DELAY_IMPORT_ATTRIBUTE_DLATTR_RVA;
    if (unknownAttributeBits !== 0) {
      warnings.add(
        `Delay import descriptor sets unknown Attributes bits (${toHex32(unknownAttributeBits, 8)}).`
      );
    }
    if (!DllNameRVA) {
      warnings.add("Delay import descriptor is missing the DLL name RVA.");
      continue;
    }
    const nameOff = rvaToOff(DllNameRVA);
    if (DllNameRVA && nameOff == null) warnings.add("Delay import name RVA does not map to file data.");
    const intRva = ImportNameTableRVA >>> 0;
    const intOff = intRva ? rvaToOff(intRva) : null;
    const thunkTable = !intRva
      ? { functions: [], terminated: true }
      : intOff == null
        ? (warnings.add("Delay Import Name Table RVA does not map to file data."), { functions: [], terminated: false })
        : await readDelayThunkFunctions(
            reader,
            rvaToOff,
            intRva,
            warnings,
            maxThunkEntries
          );
    if (intRva && !thunkTable.terminated) warnings.add("Delay-load thunk table is not terminated by a null entry.");
    entries.push({
      name:
        nameOff != null
          ? await readDelayImportName(reader, rvaToOff, DllNameRVA, warnings)
          : "",
      Attributes,
      ModuleHandleRVA,
      ImportAddressTableRVA,
      ImportNameTableRVA,
      BoundImportAddressTableRVA,
      UnloadInformationTableRVA,
      TimeDateStamp,
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
