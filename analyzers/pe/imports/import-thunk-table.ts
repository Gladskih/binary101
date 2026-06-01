"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { readMappedNullTerminatedAsciiString } from "../strings/mapped-ascii-string.js";
import type { RvaToOffset } from "../types.js";
import type { PeImportFunction } from "./index.js";

// Microsoft PE format, Import Lookup Table / Import Address Table:
// PE32 uses 32-bit thunks and PE32+ uses 64-bit thunks.
export const IMAGE_THUNK_DATA32_SIZE = Uint32Array.BYTES_PER_ELEMENT;
export const IMAGE_THUNK_DATA64_SIZE = BigUint64Array.BYTES_PER_ELEMENT;

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

export type PeParsedThunkTable = { functions: PeImportFunction[]; terminated: boolean };
export type ReadImportThunkFunctions = (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  thunkRva: number,
  addWarning: (msg: string) => void,
  isReadableOffset: (offset: number | null) => offset is number,
  maxThunkEntries: (entrySize: number) => number
) => Promise<PeParsedThunkTable>;

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

export const readImportThunkFunctions32: ReadImportThunkFunctions = async (
  reader,
  fileSize,
  rvaToOff,
  thunkRva,
  addWarning,
  isReadableOffset,
  maxThunkEntries
) => {
  const functions: PeImportFunction[] = [];
  for (let thunkIndex = 0; thunkIndex < maxThunkEntries(IMAGE_THUNK_DATA32_SIZE); thunkIndex += 1) {
    const thunkEntryRva = thunkRva + thunkIndex * IMAGE_THUNK_DATA32_SIZE;
    const thunkEntryOffset = rvaToOff(thunkEntryRva >>> 0);
    if (!isReadableOffset(thunkEntryOffset)) {
      addWarning("Import thunk RVA does not map to file data.");
      break;
    }
    const view = await reader.read(thunkEntryOffset, IMAGE_THUNK_DATA32_SIZE);
    if (view.byteLength < IMAGE_THUNK_DATA32_SIZE) {
      addWarning("Import thunks truncated (32-bit).");
      break;
    }
    const value = view.getUint32(0, true);
    if (value === 0) return { functions, terminated: true };
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

export const readImportThunkFunctions64: ReadImportThunkFunctions = async (
  reader,
  fileSize,
  rvaToOff,
  thunkRva,
  addWarning,
  isReadableOffset,
  maxThunkEntries
) => {
  const functions: PeImportFunction[] = [];
  for (let thunkIndex = 0; thunkIndex < maxThunkEntries(IMAGE_THUNK_DATA64_SIZE); thunkIndex += 1) {
    const thunkEntryRva = thunkRva + thunkIndex * IMAGE_THUNK_DATA64_SIZE;
    const thunkEntryOffset = rvaToOff(thunkEntryRva >>> 0);
    if (!isReadableOffset(thunkEntryOffset)) {
      addWarning("Import thunk RVA does not map to file data.");
      break;
    }
    const view = await reader.read(thunkEntryOffset, IMAGE_THUNK_DATA64_SIZE);
    if (view.byteLength < IMAGE_THUNK_DATA64_SIZE) {
      addWarning("Import thunks truncated (64-bit).");
      break;
    }
    const value = view.getBigUint64(0, true);
    if (value === 0n) return { functions, terminated: true };
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
