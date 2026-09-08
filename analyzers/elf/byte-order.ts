import type { ElfByteOrder } from "./binary-layout-types.js";

export interface ElfIntegerReader {
  u16: (view: DataView, offset: number) => number;
  u32: (view: DataView, offset: number) => number;
  i32: (view: DataView, offset: number) => number;
  u64: (view: DataView, offset: number) => bigint;
  i64: (view: DataView, offset: number) => bigint;
}

// DataView's built-in littleEndian argument describes byte order. These fixed readers
// are selected once; no application control flags are passed through the parsers.
export const ELF_INTEGER_READERS: Record<ElfByteOrder, ElfIntegerReader> = {
  little: {
    u16: (view, offset) => view.getUint16(offset, true),
    u32: (view, offset) => view.getUint32(offset, true),
    i32: (view, offset) => view.getInt32(offset, true),
    u64: (view, offset) => view.getBigUint64(offset, true),
    i64: (view, offset) => view.getBigInt64(offset, true)
  },
  big: {
    u16: (view, offset) => view.getUint16(offset, false),
    u32: (view, offset) => view.getUint32(offset, false),
    i32: (view, offset) => view.getInt32(offset, false),
    u64: (view, offset) => view.getBigUint64(offset, false),
    i64: (view, offset) => view.getBigInt64(offset, false)
  }
};
