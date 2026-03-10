"use strict";

// mach-o/nlist.h: sizeof(struct nlist_64) == 16.
const NLIST64_SIZE = 16;
// mach-o/nlist.h: sizeof(struct nlist) == 12.
const NLIST32_SIZE = 12;

const writeNlist64 = (
  bytes: Uint8Array,
  entryOffset: number,
  options: {
    stringIndex: number;
    type: number;
    sectionIndex: number;
    description: number;
    value: bigint;
  }
): void => {
  // mach-o/nlist.h: nlist_64 stores n_strx/u32, n_type/u8, n_sect/u8,
  // n_desc/u16, n_value/u64 in that order.
  const view = new DataView(bytes.buffer, bytes.byteOffset + entryOffset, NLIST64_SIZE);
  view.setUint32(0, options.stringIndex, true);
  bytes[entryOffset + 4] = options.type;
  bytes[entryOffset + 5] = options.sectionIndex;
  view.setUint16(6, options.description, true);
  view.setBigUint64(8, options.value, true);
};

const writeNlist32 = (
  bytes: Uint8Array,
  entryOffset: number,
  options: {
    stringIndex: number;
    type: number;
    sectionIndex: number;
    description: number;
    value: number;
  }
): void => {
  // mach-o/nlist.h: nlist stores n_strx/u32, n_type/u8, n_sect/u8,
  // n_desc/u16, n_value/u32 in that order.
  const view = new DataView(bytes.buffer, bytes.byteOffset + entryOffset, NLIST32_SIZE);
  view.setUint32(0, options.stringIndex, true);
  bytes[entryOffset + 4] = options.type;
  bytes[entryOffset + 5] = options.sectionIndex;
  view.setUint16(6, options.description, true);
  view.setUint32(8, options.value, true);
};

export { NLIST32_SIZE, NLIST64_SIZE, writeNlist32, writeNlist64 };
