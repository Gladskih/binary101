"use strict";

const encoder = new TextEncoder();

export const IMAGE_DELAYLOAD_DESCRIPTOR_SIZE = 32; // IMAGE_DELAYLOAD_DESCRIPTOR
export const IMAGE_THUNK_DATA32_SIZE = 4; // IMAGE_THUNK_DATA32
export const IMAGE_THUNK_DATA64_SIZE = 8; // IMAGE_THUNK_DATA64
export const IMAGE_IMPORT_BY_NAME_HINT_SIZE = 2; // Hint field before the import name string.
export const IMAGE_ORDINAL_FLAG64 = 0x8000000000000000n; // IMAGE_ORDINAL_FLAG64

// Microsoft PE format, Delay-Load Directory Table:
// IMAGE_DELAYLOAD_DESCRIPTOR keeps these DWORD fields at fixed offsets.
const DELAYLOAD_DESCRIPTOR_FIELD_OFFSET = {
  attributes: 0,
  dllNameRva: 4,
  importNameTableRva: 16,
  timeDateStamp: 28
} as const;

type DelayImportDescriptorFields = {
  attributes?: number;
  dllNameRva: number;
  importNameTableRva: number;
  timeDateStamp?: number;
};

export const createDelayImportLayout = (
  start = IMAGE_DELAYLOAD_DESCRIPTOR_SIZE
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

export const writeDelayImportDescriptor = (
  view: DataView,
  descriptorOffset: number,
  fields: DelayImportDescriptorFields
): void => {
  view.setUint32(
    descriptorOffset + DELAYLOAD_DESCRIPTOR_FIELD_OFFSET.attributes,
    fields.attributes ?? 0,
    true
  );
  view.setUint32(
    descriptorOffset + DELAYLOAD_DESCRIPTOR_FIELD_OFFSET.dllNameRva,
    fields.dllNameRva,
    true
  );
  view.setUint32(
    descriptorOffset + DELAYLOAD_DESCRIPTOR_FIELD_OFFSET.importNameTableRva,
    fields.importNameTableRva,
    true
  );
  view.setUint32(
    descriptorOffset + DELAYLOAD_DESCRIPTOR_FIELD_OFFSET.timeDateStamp,
    fields.timeDateStamp ?? 0,
    true
  );
};

export const writeDelayImportName = (
  bytes: Uint8Array,
  dllNameRva: number,
  dllName: string
): void => {
  encoder.encodeInto(`${dllName}\0`, new Uint8Array(bytes.buffer, dllNameRva));
};

export const writeImportByName = (
  bytes: Uint8Array,
  view: DataView,
  hintNameRva: number,
  hint: number,
  name: string
): void => {
  view.setUint16(hintNameRva, hint, true);
  encoder.encodeInto(
    `${name}\0`,
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
