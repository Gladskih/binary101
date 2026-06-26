"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeImportMetadataEntry } from "../../../pe-import-metadata-schema.js";
import type { WinapiMetadataEntry } from "../../../winapi-metadata-schema.js";
import { readMappedNullTerminatedAsciiString } from "../strings/mapped-ascii-string.js";
import type { RvaToOffset } from "../types.js";

const IMAGE_THUNK_DATA32_SIZE = Uint32Array.BYTES_PER_ELEMENT;
const IMAGE_THUNK_DATA64_SIZE = BigUint64Array.BYTES_PER_ELEMENT; // PE32+ uses 64-bit thunks.
const IMAGE_IMPORT_BY_NAME_HINT_SIZE = Uint16Array.BYTES_PER_ELEMENT; // PE format, Hint/Name Table.
const IMAGE_ORDINAL_FLAG32 = 0x80000000; // PE32 import-by-ordinal flag.
const IMAGE_ORDINAL_FLAG64 = 0x8000000000000000n; // PE32+ import-by-ordinal flag.
const IMAGE_ORDINAL_MASK32 = 0xffff; // winnt.h: import-by-ordinal stores the ordinal in the low 16 bits.
const IMAGE_ORDINAL_MASK64 = 0xffffn; // winnt.h: import-by-ordinal stores the ordinal in the low 16 bits.
const IMAGE_DELAY_IMPORT_ORDINAL_RESERVED_MASK32 = 0x7fff0000; // PE32 ordinal thunks reserve bits 30-15.
const IMAGE_DELAY_IMPORT_NAME_MASK64 = 0x7fffffffn; // PE32+ keeps the import-by-name RVA in bits 30-0.
const IMAGE_DELAY_IMPORT_NAME_RESERVED_MASK64 = 0x7fffffff80000000n; // PE32+ reserves bits 62-31.
const IMAGE_DELAY_IMPORT_ORDINAL_RESERVED_MASK64 = 0x7fffffffffff0000n; // PE32+ ordinal thunks reserve bits 62-16.

export interface PeDelayImportFunction {
  ordinal?: number;
  hint?: number;
  name?: string;
  apiMetadata?: PeImportMetadataEntry;
  winapiMetadata?: WinapiMetadataEntry;
}
export type DelayThunkTable = { functions: PeDelayImportFunction[]; terminated: boolean };
export type ReadDelayThunkFunctions = (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  importNameTableRva: number,
  warnings: Set<string>,
  maxThunkEntries: (entrySize: number) => number
) => Promise<DelayThunkTable>;

const readDelayImportHintName = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  hintNameRva: number,
  warnings: Set<string>
): Promise<PeDelayImportFunction> => {
  const hintNameOff = rvaToOff(hintNameRva);
  if (hintNameOff == null || hintNameOff < 0 || hintNameOff >= reader.size) {
    warnings.add("Delay import hint/name RVA does not map to file data.");
    return { name: "<bad RVA>" };
  }
  const hintView = await reader.read(hintNameOff, IMAGE_IMPORT_BY_NAME_HINT_SIZE);
  if (hintView.byteLength < IMAGE_IMPORT_BY_NAME_HINT_SIZE) {
    warnings.add("Delay import hint/name table truncated.");
    return { name: "" };
  }
  const hint = hintView.getUint16(0, true);
  const result = await readMappedNullTerminatedAsciiString(
    reader,
    reader.size,
    rvaToOff,
    (hintNameRva + IMAGE_IMPORT_BY_NAME_HINT_SIZE) >>> 0,
    reader.size
  );
  if (!result) {
    warnings.add("Delay import hint/name RVA does not map to file data.");
    return { hint, name: "" };
  }
  if (!result.terminated) warnings.add("Delay import name string truncated.");
  return { hint, name: result.text };
};

export const readDelayThunkFunctions32: ReadDelayThunkFunctions = async (
  reader,
  rvaToOff,
  importNameTableRva,
  warnings,
  maxThunkEntries
) => {
  const functions: PeDelayImportFunction[] = [];
  for (let index = 0; index < maxThunkEntries(IMAGE_THUNK_DATA32_SIZE); index += 1) {
    const thunkEntryRva = importNameTableRva + index * IMAGE_THUNK_DATA32_SIZE;
    const thunkEntryOff = rvaToOff(thunkEntryRva >>> 0);
    if (thunkEntryOff == null) {
      warnings.add("Delay import thunk RVA does not map to file data.");
      break;
    }
    if (thunkEntryOff < 0 || thunkEntryOff + IMAGE_THUNK_DATA32_SIZE > reader.size) {
      warnings.add("Delay import thunk table truncated (32-bit).");
      break;
    }
    const thunkView = await reader.read(thunkEntryOff, IMAGE_THUNK_DATA32_SIZE);
    if (thunkView.byteLength < IMAGE_THUNK_DATA32_SIZE) {
      warnings.add("Delay import thunk table truncated (32-bit).");
      break;
    }
    const value = thunkView.getUint32(0, true);
    if (value === 0) return { functions, terminated: true };
    if ((value & IMAGE_ORDINAL_FLAG32) !== 0) {
      if ((value & IMAGE_DELAY_IMPORT_ORDINAL_RESERVED_MASK32) !== 0) {
        warnings.add("Delay import ordinal thunk has reserved bits set.");
      }
      functions.push({ ordinal: value & IMAGE_ORDINAL_MASK32 });
      continue;
    }
    functions.push(await readDelayImportHintName(reader, rvaToOff, value, warnings));
  }
  return { functions, terminated: false };
};

export const readDelayThunkFunctions64: ReadDelayThunkFunctions = async (
  reader,
  rvaToOff,
  importNameTableRva,
  warnings,
  maxThunkEntries
) => {
  const functions: PeDelayImportFunction[] = [];
  for (let index = 0; index < maxThunkEntries(IMAGE_THUNK_DATA64_SIZE); index += 1) {
    const thunkEntryRva = importNameTableRva + index * IMAGE_THUNK_DATA64_SIZE;
    const thunkEntryOff = rvaToOff(thunkEntryRva >>> 0);
    if (thunkEntryOff == null) {
      warnings.add("Delay import thunk RVA does not map to file data.");
      break;
    }
    if (thunkEntryOff < 0 || thunkEntryOff + IMAGE_THUNK_DATA64_SIZE > reader.size) {
      warnings.add("Delay import thunk table truncated (64-bit).");
      break;
    }
    const thunkView = await reader.read(thunkEntryOff, IMAGE_THUNK_DATA64_SIZE);
    if (thunkView.byteLength < IMAGE_THUNK_DATA64_SIZE) {
      warnings.add("Delay import thunk table truncated (64-bit).");
      break;
    }
    const value = thunkView.getBigUint64(0, true);
    if (value === 0n) return { functions, terminated: true };
    if ((value & IMAGE_ORDINAL_FLAG64) !== 0n) {
      if ((value & IMAGE_DELAY_IMPORT_ORDINAL_RESERVED_MASK64) !== 0n) {
        warnings.add("Delay import ordinal thunk has reserved bits set.");
      }
      functions.push({ ordinal: Number(value & IMAGE_ORDINAL_MASK64) });
      continue;
    }
    if ((value & IMAGE_DELAY_IMPORT_NAME_RESERVED_MASK64) !== 0n) {
      warnings.add("Delay import name thunk has reserved bits set.");
    }
    functions.push(
      await readDelayImportHintName(
        reader,
        rvaToOff,
        Number(value & IMAGE_DELAY_IMPORT_NAME_MASK64),
        warnings
      )
    );
  }
  return { functions, terminated: false };
};
