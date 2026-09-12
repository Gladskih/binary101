"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { mappedRvaSize } from "./rva-mapping.js";
import { readMappedRvaPrefix } from "./rva-byte-reader.js";
import type { RvaToOffset } from "./types.js";

/** A bounded, zero-based view of an RVA range for nested, relative-offset formats. */
export const createRvaRangeReader = (
  reader: FileRangeReader, rvaToOff: RvaToOffset, rva: number, byteLength: number
): FileRangeReader => {
  const size = mappedRvaSize(rvaToOff, rva, byteLength, reader.size);
  const read = (offset: number, length: number): Promise<DataView> =>
    !Number.isSafeInteger(offset) || offset < 0 || offset >= size ||
    !Number.isSafeInteger(length) || length <= 0
      ? Promise.resolve(new DataView(new ArrayBuffer(0)))
      : readMappedRvaPrefix(reader, rva + offset, Math.min(length, size - offset), rvaToOff);
  const readBytes = async (offset: number, length: number): Promise<Uint8Array> => {
    const view = await read(offset, length);
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  };
  return { size, read, readBytes };
};
