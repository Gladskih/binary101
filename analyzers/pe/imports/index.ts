"use strict";

import type { PeDataDirectory, RvaToOffset } from "../types.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import { readMappedNullTerminatedAsciiString } from "../strings/mapped-ascii-string.js";

// Microsoft PE format, Import Directory Table: IMAGE_IMPORT_DESCRIPTOR is five DWORDs.
const IMAGE_IMPORT_DESCRIPTOR_SIZE = 20;
// Microsoft PE format, Import Lookup Table / Import Address Table:
// PE32 uses 32-bit thunks and PE32+ uses 64-bit thunks.
const IMAGE_THUNK_DATA32_SIZE = Uint32Array.BYTES_PER_ELEMENT;
const IMAGE_THUNK_DATA64_SIZE = BigUint64Array.BYTES_PER_ELEMENT;
const IMAGE_IMPORT_BY_NAME_HINT_SIZE = Uint16Array.BYTES_PER_ELEMENT; // PE format, Hint/Name Table.
const IMAGE_ORDINAL_FLAG32 = 0x80000000; // PE32 import-by-ordinal flag.
const IMAGE_ORDINAL_FLAG64 = 0x8000000000000000n; // PE32+ import-by-ordinal flag.
const IMAGE_ORDINAL_MASK32 = 0xffff; // winnt.h: import-by-ordinal stores the ordinal in the low 16 bits.
const IMAGE_ORDINAL_MASK64 = 0xffffn; // winnt.h: import-by-ordinal stores the ordinal in the low 16 bits.
const IMAGE_IMPORT_ORDINAL_RESERVED_MASK32 = 0x7fff0000; // PE32 ordinal thunks reserve bits 30-15.
// Microsoft PE format: PE32+ name thunks keep a 31-bit RVA in bits 30-0 and reserve bits 62-31.
const IMAGE_IMPORT_NAME_MASK64 = 0x7fffffffn; // PE32+ keeps the import-by-name RVA in bits 30-0.
const IMAGE_IMPORT_NAME_RESERVED_MASK64 = 0x7fffffff80000000n; // PE32+ reserves bits 62-31.
const IMAGE_IMPORT_ORDINAL_RESERVED_MASK64 = 0x7fffffffffff0000n; // PE32+ ordinal thunks reserve bits 62-16.

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
type PeParsedThunkTable = { functions: PeImportFunction[]; terminated: boolean };

const readImportByName = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  hintNameRva: number,
  addWarning: (msg: string) => void,
  isReadableOffset: (offset: number | null) => offset is number
): Promise<PeImportFunction> => {
  const hintNameOffset = rvaToOff(hintNameRva);
  if (!isReadableOffset(hintNameOffset)) {
    addWarning("Import hint/name RVA does not map to file data.");
    return { name: "<bad RVA>" };
  }
  const hintView = await reader.read(hintNameOffset, IMAGE_IMPORT_BY_NAME_HINT_SIZE);
  if (hintView.byteLength < IMAGE_IMPORT_BY_NAME_HINT_SIZE) {
    addWarning("Import hint/name table truncated.");
    return { name: "" };
  }
  const hint = hintView.getUint16(0, true);
  const hintName = await readMappedNullTerminatedAsciiString(
    reader,
    fileSize,
    rvaToOff,
    (hintNameRva + IMAGE_IMPORT_BY_NAME_HINT_SIZE) >>> 0,
    fileSize
  );
  if (hintName && !hintName.terminated) addWarning("Import name string truncated.");
  return { hint, name: hintName?.text ?? "" };
};

const readImportThunkFunctions32 = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  thunkRva: number,
  addWarning: (msg: string) => void,
  isReadableOffset: (offset: number | null) => offset is number,
  maxThunkEntries: (entrySize: number) => number
): Promise<PeParsedThunkTable> => {
  const functions: PeImportFunction[] = [];
  for (let thunkIndex = 0; thunkIndex < maxThunkEntries(IMAGE_THUNK_DATA32_SIZE); thunkIndex += 1) {
    const thunkEntryRva = thunkRva + thunkIndex * IMAGE_THUNK_DATA32_SIZE;
    const thunkEntryOffset = rvaToOff(thunkEntryRva >>> 0);
    if (!isReadableOffset(thunkEntryOffset)) {
      addWarning("Import thunk RVA does not map to file data.");
      break;
    }
    const dv = await reader.read(thunkEntryOffset, IMAGE_THUNK_DATA32_SIZE);
    if (dv.byteLength < IMAGE_THUNK_DATA32_SIZE) {
      addWarning("Import thunks truncated (32-bit).");
      break;
    }
    const value = dv.getUint32(0, true);
    if (value === 0) {
      return { functions, terminated: true };
    }
    if ((value & IMAGE_ORDINAL_FLAG32) !== 0) {
      if ((value & IMAGE_IMPORT_ORDINAL_RESERVED_MASK32) !== 0) {
        addWarning("Import ordinal thunk has reserved bits set.");
      }
      functions.push({ ordinal: value & IMAGE_ORDINAL_MASK32 });
      continue;
    }
    functions.push(
      await readImportByName(reader, fileSize, rvaToOff, value, addWarning, isReadableOffset)
    );
  }
  return { functions, terminated: false };
};

const readImportThunkFunctions64 = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  thunkRva: number,
  addWarning: (msg: string) => void,
  isReadableOffset: (offset: number | null) => offset is number,
  maxThunkEntries: (entrySize: number) => number
): Promise<PeParsedThunkTable> => {
  const functions: PeImportFunction[] = [];
  for (let thunkIndex = 0; thunkIndex < maxThunkEntries(IMAGE_THUNK_DATA64_SIZE); thunkIndex += 1) {
    const thunkEntryRva = thunkRva + thunkIndex * IMAGE_THUNK_DATA64_SIZE;
    const thunkEntryOffset = rvaToOff(thunkEntryRva >>> 0);
    if (!isReadableOffset(thunkEntryOffset)) {
      addWarning("Import thunk RVA does not map to file data.");
      break;
    }
    const dv = await reader.read(thunkEntryOffset, IMAGE_THUNK_DATA64_SIZE);
    if (dv.byteLength < IMAGE_THUNK_DATA64_SIZE) {
      addWarning("Import thunks truncated (64-bit).");
      break;
    }
    const value = dv.getBigUint64(0, true);
    if (value === 0n) {
      return { functions, terminated: true };
    }
    if ((value & IMAGE_ORDINAL_FLAG64) !== 0n) {
      if ((value & IMAGE_IMPORT_ORDINAL_RESERVED_MASK64) !== 0n) {
        addWarning("Import ordinal thunk has reserved bits set.");
      }
      functions.push({ ordinal: Number(value & IMAGE_ORDINAL_MASK64) });
      continue;
    }
    if ((value & IMAGE_IMPORT_NAME_RESERVED_MASK64) !== 0n) {
      addWarning("Import name thunk has reserved bits set.");
    }
    functions.push(
      await readImportByName(
        reader,
        fileSize,
        rvaToOff,
        Number(value & IMAGE_IMPORT_NAME_MASK64),
        addWarning,
        isReadableOffset
      )
    );
  }
  return { functions, terminated: false };
};

const parseImportDirectoryWithThunkReader = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  readThunkFunctions: (
    reader: FileRangeReader,
    fileSize: number,
    rvaToOff: RvaToOffset,
    thunkRva: number,
    addWarning: (msg: string) => void,
    isReadableOffset: (offset: number | null) => offset is number,
    maxThunkEntries: (entrySize: number) => number
  ) => Promise<PeParsedThunkTable>,
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
    if (!originalFirstThunk && !timeDateStamp && !forwarderChain && !nameRva && !firstThunk) break;
    if (!nameRva) {
      addWarning("Import descriptor is missing the DLL name RVA.");
      if (descriptorTruncated) break;
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
    if (descriptorTruncated) break;
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
