"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { readMappedRvaBytes } from "../rva-byte-reader.js";
import type { RvaToOffset } from "../types.js";

export type ResourcePayloadReader = FileRangeReader & {
  readResourceBytes?: (rva: number, size: number) => Promise<Uint8Array>;
};

export const createResourcePayloadReader = (
  reader: FileRangeReader, rvaToOff: RvaToOffset
): ResourcePayloadReader => ({
  size: reader.size,
  read: (offset, size) => reader.read(offset, size),
  readBytes: (offset, size) => reader.readBytes(offset, size),
  readResourceBytes: (rva, size) => readMappedRvaBytes(reader, rva, size, rvaToOff)
});
