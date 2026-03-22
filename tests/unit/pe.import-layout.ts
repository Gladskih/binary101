"use strict";

const encoder = new TextEncoder();

// Microsoft PE format, Import Directory Table / Import Lookup Table / Hint-Name Table:
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-lookup-table
export const IMAGE_IMPORT_DESCRIPTOR_SIZE = 20;
export const IMPORT_DIRECTORY_SIZE = IMAGE_IMPORT_DESCRIPTOR_SIZE * 2; // One descriptor plus the null terminator.
export const IMAGE_THUNK_DATA32_SIZE = 4; // PE32 thunk entries are 32-bit RVAs or ordinal markers.
export const IMAGE_THUNK_DATA64_SIZE = 8; // PE32+ thunk entries are 64-bit RVAs or ordinal markers.
export const IMAGE_IMPORT_BY_NAME_HINT_SIZE = 2; // 16-bit hint before the NUL-terminated ASCII import name.
export const IMAGE_ORDINAL_FLAG64 = 0x8000000000000000n;

const IMPORT_DESCRIPTOR_FIELD_OFFSET = {
  originalFirstThunk: 0,
  timeDateStamp: 4,
  forwarderChain: 8,
  dllNameRva: 12,
  firstThunk: 16
} as const;

type ImportDescriptorFields = {
  originalFirstThunk?: number;
  timeDateStamp?: number;
  forwarderChain?: number;
  dllNameRva?: number;
  firstThunk?: number;
};

export const createImportLayout = (
  start = IMPORT_DIRECTORY_SIZE
): { reserve: (size: number) => number; size: () => number } => {
  let next = start;
  return {
    reserve: (size: number): number => {
      const offset = next;
      next += size;
      return offset;
    },
    size: (): number => next
  };
};

export const cStringSize = (text: string): number => encoder.encode(`${text}\0`).length;

export const imageImportByNameSize = (name: string): number =>
  IMAGE_IMPORT_BY_NAME_HINT_SIZE + cStringSize(name);

export const writeImportDescriptor = (
  view: DataView,
  descriptorOffset: number,
  fields: ImportDescriptorFields
): void => {
  view.setUint32(
    descriptorOffset + IMPORT_DESCRIPTOR_FIELD_OFFSET.originalFirstThunk,
    fields.originalFirstThunk ?? 0,
    true
  );
  view.setUint32(
    descriptorOffset + IMPORT_DESCRIPTOR_FIELD_OFFSET.timeDateStamp,
    fields.timeDateStamp ?? 0,
    true
  );
  view.setUint32(
    descriptorOffset + IMPORT_DESCRIPTOR_FIELD_OFFSET.forwarderChain,
    fields.forwarderChain ?? 0,
    true
  );
  view.setUint32(
    descriptorOffset + IMPORT_DESCRIPTOR_FIELD_OFFSET.dllNameRva,
    fields.dllNameRva ?? 0,
    true
  );
  view.setUint32(
    descriptorOffset + IMPORT_DESCRIPTOR_FIELD_OFFSET.firstThunk,
    fields.firstThunk ?? 0,
    true
  );
};

export const writeImportName = (
  bytes: Uint8Array,
  dllNameRva: number,
  dllName: string,
  withTerminator = true
): void => {
  encoder.encodeInto(
    withTerminator ? `${dllName}\0` : dllName,
    new Uint8Array(bytes.buffer, dllNameRva)
  );
};

export const writeImportByName = (
  bytes: Uint8Array,
  view: DataView,
  hintNameRva: number,
  hint: number,
  name: string,
  withTerminator = true
): void => {
  view.setUint16(hintNameRva, hint, true);
  encoder.encodeInto(
    withTerminator ? `${name}\0` : name,
    new Uint8Array(bytes.buffer, hintNameRva + IMAGE_IMPORT_BY_NAME_HINT_SIZE)
  );
};

export const writeThunkTable32 = (
  view: DataView,
  thunkTableRva: number,
  thunks: number[]
): void => {
  thunks.forEach((thunk, index) => {
    view.setUint32(thunkTableRva + index * IMAGE_THUNK_DATA32_SIZE, thunk, true);
  });
};

export const writeThunkTable64 = (
  view: DataView,
  thunkTableRva: number,
  thunks: bigint[]
): void => {
  thunks.forEach((thunk, index) => {
    view.setBigUint64(thunkTableRva + index * IMAGE_THUNK_DATA64_SIZE, thunk, true);
  });
};

export const createUnmappedRva = (bytes: Uint8Array, gap = 1): number => bytes.length + gap;

export const placeAtEnd = (bytes: Uint8Array, size: number): number => bytes.length - size;

export const createOrdinalThunk32 = (ordinal: number, reservedBits = 0): number =>
  0x80000000 | ((reservedBits & 0x7fff) << 16) | ordinal;

export const createOrdinalThunk64 = (ordinal: number, reservedBits = 0n): bigint =>
  IMAGE_ORDINAL_FLAG64 | (reservedBits << 16n) | BigInt(ordinal);

export const createNameThunk64 = (hintNameRva: number, reservedBits = 0n): bigint =>
  (reservedBits << 31n) | BigInt(hintNameRva);

export const createHintValue = (lowByteSource: number, highByteSource: number): number =>
  (lowByteSource & 0xff) | ((highByteSource & 0xff) << 8);

export const createLimitedImportSliceFile = (
  bytes: Uint8Array,
  maxSlices: number,
  name = "tracked.bin"
): File => {
  let sliceCount = 0;
  return {
    lastModified: 0,
    name,
    size: bytes.length,
    type: "application/octet-stream",
    webkitRelativePath: "",
    slice(start?: number, end?: number, contentType?: string): Blob {
      sliceCount += 1;
      if (sliceCount > maxSlices) throw new Error("Too many import string reads");
      const sliceStart = Math.max(0, Math.trunc(start ?? 0));
      const sliceEnd = Math.max(sliceStart, Math.trunc(end ?? bytes.length));
      return new Blob([bytes.slice(sliceStart, sliceEnd)], {
        type: contentType ?? "application/octet-stream"
      });
    }
  } as File;
};
