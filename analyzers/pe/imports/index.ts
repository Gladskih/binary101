"use strict";

import type { PeDataDirectory, RvaToOffset } from "../types.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import { readMappedNullTerminatedAsciiString } from "../strings/mapped-ascii-string.js";
import {
  IMAGE_THUNK_DATA32_SIZE,
  IMAGE_THUNK_DATA64_SIZE,
  type ReadImportThunkFunctions,
  readImportThunkFunctions32,
  readImportThunkFunctions64
} from "./import-thunk-table.js";

// Microsoft PE format, Import Directory Table: IMAGE_IMPORT_DESCRIPTOR is five DWORDs.
const IMAGE_IMPORT_DESCRIPTOR_SIZE = 20;

export interface PeImportFunction { ordinal?: number; hint?: number; name?: string }

export type PeImportLookupSource = "import-lookup-table" | "iat-fallback" | "missing";

export interface PeImportEntry {
  dll: string;
  originalFirstThunkRva: number;
  timeDateStamp: number;
  forwarderChain: number;
  firstThunkRva: number;
  lookupSource: PeImportLookupSource;
  thunkTableTerminated: boolean;
  functions: PeImportFunction[];
}

export interface PeImportParseResult { entries: PeImportEntry[]; thunkEntrySize: number; warning?: string }

const parseImportDirectoryWithThunkReader = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  readThunkFunctions: ReadImportThunkFunctions,
  thunkEntrySize: number
): Promise<PeImportParseResult> => {
  const impDir = dataDirs.find(d => d.name === "IMPORT");
  const imports: PeImportEntry[] = [];
  const warnings = new Set<string>();
  const isReadableOffset = (offset: number | null): offset is number =>
    offset != null && offset >= 0 && offset < reader.size;
  const maxThunkEntries = (entrySize: number): number => Math.floor(reader.size / entrySize) + 1;
  if (!impDir || (impDir.rva === 0 && impDir.size === 0)) return { entries: imports, thunkEntrySize };
  if (impDir.rva === 0) return {
    entries: imports,
    thunkEntrySize,
    warning: "Import directory has a non-zero size but RVA is 0."
  };
  if (impDir.size === 0) return {
    entries: imports,
    thunkEntrySize,
    warning: "Import directory has an RVA but size is 0."
  };
  const start = rvaToOff(impDir.rva);
  if (start == null || start < 0 || start >= reader.size) {
    return { entries: imports, thunkEntrySize, warning: "Import directory RVA does not map to file data." };
  }
  const availableDirSize = Math.max(0, Math.min(impDir.size, reader.size - start));
  const maxDescriptors = Math.ceil(availableDirSize / IMAGE_IMPORT_DESCRIPTOR_SIZE);
  const addWarning = (msg: string): void => {
    warnings.add(msg);
  };
  let descriptorTableTerminated = false;
  let descriptorScanStopped = false;
  for (let index = 0; index < maxDescriptors; index += 1) {
    const descriptorRva = (impDir.rva + index * IMAGE_IMPORT_DESCRIPTOR_SIZE) >>> 0;
    const offset = rvaToOff(descriptorRva);
    const descriptorSize = Math.min(
      IMAGE_IMPORT_DESCRIPTOR_SIZE,
      Math.max(0, availableDirSize - index * IMAGE_IMPORT_DESCRIPTOR_SIZE)
    );
    if (descriptorSize <= 0) break;
    if (!isReadableOffset(offset)) {
      addWarning("Import descriptor RVA does not map to file data.");
      descriptorScanStopped = true;
      break;
    }
    const descriptorTruncated = descriptorSize < IMAGE_IMPORT_DESCRIPTOR_SIZE;
    const desc = await reader.read(offset, descriptorSize);
    const readDescriptorField = (fieldOffset: number, fieldName: string): number | null => {
      if (desc.byteLength < fieldOffset + 4) {
        addWarning(`Import descriptor is truncated before the ${fieldName} field.`);
        return null;
      }
      return desc.getUint32(fieldOffset, true);
    };
    const originalFirstThunk = readDescriptorField(0, "OriginalFirstThunk") ?? 0;
    const timeDateStamp = readDescriptorField(4, "TimeDateStamp") ?? 0;
    const forwarderChain = readDescriptorField(8, "ForwarderChain") ?? 0;
    const nameRva = readDescriptorField(12, "name RVA") ?? 0;
    const firstThunk = readDescriptorField(16, "thunk RVA") ?? 0;
    if (!originalFirstThunk && !timeDateStamp && !forwarderChain && !nameRva && !firstThunk) {
      descriptorTableTerminated = true;
      break;
    }
    if (!nameRva) {
      addWarning("Import descriptor is missing the DLL name RVA.");
      if (descriptorTruncated) {
        descriptorScanStopped = true;
        break;
      }
      continue;
    }
    const nameOffset = rvaToOff(nameRva);
    let dllName = "";
    if (isReadableOffset(nameOffset)) {
      const dllNameText = await readMappedNullTerminatedAsciiString(
        reader,
        reader.size,
        rvaToOff,
        nameRva >>> 0,
        reader.size
      );
      if (dllNameText) {
        dllName = dllNameText.text;
        if (!dllNameText.terminated) addWarning("Import DLL name string truncated.");
      }
    } else if (nameRva) {
      addWarning("Import name RVA does not map to file data.");
    }
    if (descriptorTruncated) {
      descriptorScanStopped = true;
      break;
    }
    // Microsoft PE format: OriginalFirstThunk points to the Import Lookup Table, while FirstThunk points to the Import Address Table that the loader patches.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table
    const lookupSource: PeImportLookupSource = originalFirstThunk
      ? "import-lookup-table"
      : firstThunk
        ? "iat-fallback"
        : "missing";
    const thunkRva = originalFirstThunk || firstThunk;
    const thunkTable = thunkRva
      ? await readThunkFunctions(
          reader,
          reader.size,
          rvaToOff,
          thunkRva,
          addWarning,
          isReadableOffset,
          maxThunkEntries
        )
      : { functions: [], terminated: false };
    if (thunkRva && !thunkTable.terminated) {
      addWarning("Import thunk table is not terminated by a null entry.");
    }
    imports.push({
      dll: dllName,
      originalFirstThunkRva: originalFirstThunk,
      timeDateStamp,
      forwarderChain,
      firstThunkRva: firstThunk,
      lookupSource,
      thunkTableTerminated: thunkTable.terminated,
      functions: thunkTable.functions
    });
  }
  if (!descriptorTableTerminated && !descriptorScanStopped) {
    addWarning("Import directory table is not terminated by an all-zero descriptor within the declared directory size.");
  }
  const warning = warnings.size ? Array.from(warnings).join(" | ") : undefined;
  return warning ? { entries: imports, thunkEntrySize, warning } : { entries: imports, thunkEntrySize };
};

export const parseImportDirectory32 = async (
  reader: FileRangeReader, dataDirs: PeDataDirectory[], rvaToOff: RvaToOffset
): Promise<PeImportParseResult> =>
  parseImportDirectoryWithThunkReader(
    reader, dataDirs, rvaToOff, readImportThunkFunctions32, IMAGE_THUNK_DATA32_SIZE
  );

export const parseImportDirectory64 = async (
  reader: FileRangeReader, dataDirs: PeDataDirectory[], rvaToOff: RvaToOffset
): Promise<PeImportParseResult> =>
  parseImportDirectoryWithThunkReader(
    reader, dataDirs, rvaToOff, readImportThunkFunctions64, IMAGE_THUNK_DATA64_SIZE
  );
