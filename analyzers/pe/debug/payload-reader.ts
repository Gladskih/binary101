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
