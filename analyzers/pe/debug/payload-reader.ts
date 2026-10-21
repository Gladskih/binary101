"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { RvaToOffset } from "../types.js";

// Debug Directory: PointerToRawData is a file pointer; AddressOfRawData is an RVA.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only
export const readDebugPayload = (
  reader: FileRangeReader, rvaToOff: RvaToOffset,
  addressOfRawData: number, pointerToRawData: number, relativeOffset: number, size: number
): Promise<DataView> => pointerToRawData
  ? reader.read(pointerToRawData + relativeOffset, size)
  : readMappedRvaPrefix(reader, addressOfRawData + relativeOffset, size, rvaToOff);

export const readDebugPayloadBytes = async (
  reader: FileRangeReader, rvaToOff: RvaToOffset,
  addressOfRawData: number, pointerToRawData: number, relativeOffset: number, size: number
): Promise<Uint8Array> => {
  const view = await readDebugPayload(reader, rvaToOff,
    addressOfRawData, pointerToRawData, relativeOffset, size);
  return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
};

/** Zero-based payload view; embedded offsets never escape its validated extent. */
export const createDebugPayloadReader = (
  reader: FileRangeReader, rvaToOff: RvaToOffset,
  addressOfRawData: number, pointerToRawData: number, size: number
): FileRangeReader => {
  const extent = Number.isSafeInteger(size) && size >= 0 ? size : 0;
  const read = (offset: number, length: number): Promise<DataView> =>
    !Number.isSafeInteger(offset) || offset < 0 || offset >= extent ||
    !Number.isSafeInteger(length) || length <= 0
      ? Promise.resolve(new DataView(new ArrayBuffer(0)))
      : readDebugPayload(reader, rvaToOff, addressOfRawData, pointerToRawData,
        offset, Math.min(length, extent - offset));
  const readBytes = async (offset: number, length: number): Promise<Uint8Array> => {
    const view = await read(offset, length);
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  };
  return { size: extent, read, readBytes };
};
