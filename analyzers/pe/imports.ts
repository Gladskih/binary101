"use strict";

import type {
  AddCoverageRegion,
  PeDataDirectory,
  RvaToOffset
} from "./types.js";
import { createPeRangeReader, type PeRangeReader } from "./range-reader.js";

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
// Parser policy: read NUL-terminated strings incrementally instead of slicing the full tail of a malformed file.
const NULL_TERMINATED_ASCII_READ_CHUNK_SIZE = 64;

export interface PeImportFunction {
  ordinal?: number;
  hint?: number;
  name?: string;
}

export interface PeImportEntry {
  dll: string;
  functions: PeImportFunction[];
}

export interface PeImportParseResult {
  entries: PeImportEntry[];
  warning?: string;
}

const readNullTerminatedAsciiString = async (
  reader: PeRangeReader,
  fileSize: number,
  offset: number
): Promise<{ text: string; truncated: boolean } | null> => {
  if (offset < 0 || offset >= fileSize) return null;
  let text = "";
  let position = offset;
  while (position < fileSize) {
    const chunkView = await reader.read(position, NULL_TERMINATED_ASCII_READ_CHUNK_SIZE);
    const chunk = new Uint8Array(
      chunkView.buffer,
      chunkView.byteOffset,
      chunkView.byteLength
    );
    if (chunk.byteLength === 0) break;
    const zeroIndex = chunk.indexOf(0);
    if (zeroIndex !== -1) {
      if (zeroIndex > 0) text += String.fromCharCode(...chunk.slice(0, zeroIndex));
      return { text, truncated: false };
    }
    text += String.fromCharCode(...chunk);
    position += chunk.byteLength;
  }
  return { text, truncated: true };
};

const readImportByName = async (
  reader: PeRangeReader,
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
  const hintName = await readNullTerminatedAsciiString(
    reader,
    fileSize,
    hintNameOffset + IMAGE_IMPORT_BY_NAME_HINT_SIZE
  );
  if (hintName?.truncated) addWarning("Import name string truncated.");
  return { hint, name: hintName?.text ?? "" };
};

const readImportThunkFunctions32 = async (
  reader: PeRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  thunkRva: number,
  addWarning: (msg: string) => void,
  isReadableOffset: (offset: number | null) => offset is number,
  maxThunkEntries: (entrySize: number) => number
): Promise<PeImportFunction[]> => {
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
    if (value === 0) break;
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
  return functions;
};

const readImportThunkFunctions64 = async (
  reader: PeRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  thunkRva: number,
  addWarning: (msg: string) => void,
  isReadableOffset: (offset: number | null) => offset is number,
  maxThunkEntries: (entrySize: number) => number
): Promise<PeImportFunction[]> => {
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
    if (value === 0n) break;
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
  return functions;
};

const parseImportDirectoryWithThunkReader = async (
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion,
  readThunkFunctions: (
    reader: PeRangeReader,
    fileSize: number,
    rvaToOff: RvaToOffset,
    thunkRva: number,
    addWarning: (msg: string) => void,
    isReadableOffset: (offset: number | null) => offset is number,
    maxThunkEntries: (entrySize: number) => number
  ) => Promise<PeImportFunction[]>
): Promise<PeImportParseResult> => {
  const impDir = dataDirs.find(d => d.name === "IMPORT");
  const imports: PeImportEntry[] = [];
  const warnings = new Set<string>();
  const isReadableOffset = (offset: number | null): offset is number =>
    offset != null && offset >= 0 && offset < file.size;
  const reader = createPeRangeReader(file, 0, file.size);
  const maxThunkEntries = (entrySize: number): number => Math.floor(file.size / entrySize) + 1;
  if (!impDir?.rva) return { entries: imports };
  const start = rvaToOff(impDir.rva);
  if (start == null || start < 0 || start >= file.size) {
    return { entries: imports, warning: "Import directory RVA does not map to file data." };
  }
  const availableDirSize = Math.max(0, Math.min(impDir.size, file.size - start));
  addCoverageRegion("IMPORT directory", start, availableDirSize);
  const maxDescriptors = Math.ceil(availableDirSize / IMAGE_IMPORT_DESCRIPTOR_SIZE);
  const addWarning = (msg: string): void => {
    warnings.add(msg);
  };
  for (let index = 0; index < maxDescriptors; index += 1) {
    const offset = start + index * IMAGE_IMPORT_DESCRIPTOR_SIZE;
    const descriptorSize = Math.min(
      IMAGE_IMPORT_DESCRIPTOR_SIZE,
      Math.max(0, availableDirSize - index * IMAGE_IMPORT_DESCRIPTOR_SIZE)
    );
    if (descriptorSize <= 0) break;
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
      const dllNameText = await readNullTerminatedAsciiString(reader, file.size, nameOffset);
      if (dllNameText) {
        dllName = dllNameText.text;
        if (dllNameText.truncated) addWarning("Import DLL name string truncated.");
      }
    } else if (nameRva) {
      addWarning("Import name RVA does not map to file data.");
    }
    if (descriptorTruncated) break;
    const thunkRva = originalFirstThunk || firstThunk;
    const functions = thunkRva
      ? await readThunkFunctions(
          reader,
          file.size,
          rvaToOff,
          thunkRva,
          addWarning,
          isReadableOffset,
          maxThunkEntries
        )
      : [];
    imports.push({ dll: dllName, functions });
  }
  const warning = warnings.size ? Array.from(warnings).join(" | ") : undefined;
  return warning ? { entries: imports, warning } : { entries: imports };
};

export const parseImportDirectory32 = async (
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<PeImportParseResult> =>
  parseImportDirectoryWithThunkReader(
    file,
    dataDirs,
    rvaToOff,
    addCoverageRegion,
    readImportThunkFunctions32
  );

export const parseImportDirectory64 = async (
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<PeImportParseResult> =>
  parseImportDirectoryWithThunkReader(
    file,
    dataDirs,
    rvaToOff,
    addCoverageRegion,
    readImportThunkFunctions64
  );
