import type { FileRangeReader } from "./file-range-reader.js";

// Decoded sections already own their bytes. Serve bounded views without making
// a second Blob/File copy of the decompressed payload.
export const createMemoryRangeReader = (bytes: Uint8Array): FileRangeReader => {
  const read = async (offset: number, size: number): Promise<DataView> => {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || offset < 0 || size < 0) {
      return new DataView(bytes.buffer, bytes.byteOffset, 0);
    }
    const start = Math.min(offset, bytes.length);
    return new DataView(bytes.buffer, bytes.byteOffset + start, Math.min(size, bytes.length - start));
  };
  return { size: bytes.length, read, readBytes: async (offset, size) => {
    const view = await read(offset, size);
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  } };
};
