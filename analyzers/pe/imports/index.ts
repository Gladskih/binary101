"use strict";

import type { PeDataDirectory, RvaToOffset } from "../types.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { WinapiMetadataEntry } from "../../../winapi-metadata-schema.js";
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

export interface PeImportFunction {
  ordinal?: number;
  hint?: number;
  name?: string;
  winapiMetadata?: WinapiMetadataEntry;
}

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

type ImportDirectoryReadState = {
  reader: FileRangeReader;
  rvaToOff: RvaToOffset;
  readThunkFunctions: ReadImportThunkFunctions;
  warnings: Set<string>;
};

type ImportDescriptor = {
  originalFirstThunk: number;
  timeDateStamp: number;
  forwarderChain: number;
  nameRva: number;
  firstThunk: number;
  truncated: boolean;
  allZero: boolean;
};

const createImportParseWarning = (warnings: Set<string>): string | undefined =>
  warnings.size ? Array.from(warnings).join(" | ") : undefined;

const readImportDescriptor = async (
  reader: FileRangeReader,
  offset: number,
  descriptorSize: number,
  warnings: Set<string>
): Promise<ImportDescriptor> => {
  const desc = await reader.read(offset, descriptorSize);
  const readDescriptorField = (fieldOffset: number, fieldName: string): number | null => {
    if (desc.byteLength < fieldOffset + 4) {
      warnings.add(`Import descriptor is truncated before the ${fieldName} field.`);
      return null;
    }
    return desc.getUint32(fieldOffset, true);
  };
  const originalFirstThunk = readDescriptorField(0, "OriginalFirstThunk") ?? 0;
  const timeDateStamp = readDescriptorField(4, "TimeDateStamp") ?? 0;
  const forwarderChain = readDescriptorField(8, "ForwarderChain") ?? 0;
  const nameRva = readDescriptorField(12, "name RVA") ?? 0;
  const firstThunk = readDescriptorField(16, "thunk RVA") ?? 0;
  return {
    originalFirstThunk,
    timeDateStamp,
    forwarderChain,
    nameRva,
    firstThunk,
    truncated: descriptorSize < IMAGE_IMPORT_DESCRIPTOR_SIZE,
    allZero: !originalFirstThunk && !timeDateStamp && !forwarderChain && !nameRva && !firstThunk
  };
};

const readImportDllName = async (
  state: ImportDirectoryReadState,
  isReadableOffset: (offset: number | null) => offset is number,
  nameRva: number
): Promise<string> => {
  const nameOffset = state.rvaToOff(nameRva);
  if (isReadableOffset(nameOffset)) {
    const dllNameText = await readMappedNullTerminatedAsciiString(
      state.reader,
      state.reader.size,
      state.rvaToOff,
      nameRva >>> 0,
      state.reader.size
    );
    if (!dllNameText) return "";
    if (!dllNameText.terminated) state.warnings.add("Import DLL name string truncated.");
    return dllNameText.text;
  }
  if (nameRva) state.warnings.add("Import name RVA does not map to file data.");
  return "";
};

const readImportFunctions = async (
  state: ImportDirectoryReadState,
  isReadableOffset: (offset: number | null) => offset is number,
  descriptor: ImportDescriptor
): Promise<{ lookupSource: PeImportLookupSource; functions: PeImportFunction[]; terminated: boolean }> => {
  const lookupSource: PeImportLookupSource = descriptor.originalFirstThunk
    ? "import-lookup-table"
    : descriptor.firstThunk
      ? "iat-fallback"
      : "missing";
  const thunkRva = descriptor.originalFirstThunk || descriptor.firstThunk;
  const maxThunkEntries = (entrySize: number): number => Math.floor(state.reader.size / entrySize) + 1;
  const thunkTable = thunkRva
    ? await state.readThunkFunctions(
        state.reader,
        state.reader.size,
        state.rvaToOff,
        thunkRva,
        message => state.warnings.add(message),
        isReadableOffset,
        maxThunkEntries
      )
    : { functions: [], terminated: false };
  if (thunkRva && !thunkTable.terminated) {
    state.warnings.add("Import thunk table is not terminated by a null entry.");
  }
  return { lookupSource, functions: thunkTable.functions, terminated: thunkTable.terminated };
};

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
  const state = { reader, rvaToOff, readThunkFunctions, warnings };
  const isReadableOffset = (offset: number | null): offset is number =>
    offset != null && offset >= 0 && offset < reader.size;
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
      warnings.add("Import descriptor RVA does not map to file data.");
      descriptorScanStopped = true;
      break;
    }
    const descriptor = await readImportDescriptor(reader, offset, descriptorSize, warnings);
    if (descriptor.allZero) {
      descriptorTableTerminated = true;
      break;
    }
    if (!descriptor.nameRva) {
      warnings.add("Import descriptor is missing the DLL name RVA.");
      if (descriptor.truncated) {
        descriptorScanStopped = true;
        break;
      }
      continue;
    }
    const dllName = await readImportDllName(state, isReadableOffset, descriptor.nameRva);
    if (descriptor.truncated) {
      descriptorScanStopped = true;
      break;
    }
    const thunkTable = await readImportFunctions(state, isReadableOffset, descriptor);
    imports.push({
      dll: dllName,
      originalFirstThunkRva: descriptor.originalFirstThunk,
      timeDateStamp: descriptor.timeDateStamp,
      forwarderChain: descriptor.forwarderChain,
      firstThunkRva: descriptor.firstThunk,
      lookupSource: thunkTable.lookupSource,
      thunkTableTerminated: thunkTable.terminated,
      functions: thunkTable.functions
    });
  }
  if (!descriptorTableTerminated && !descriptorScanStopped) {
    warnings.add("Import directory table is not terminated by an all-zero descriptor within the declared directory size.");
  }
  const warning = createImportParseWarning(warnings);
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
