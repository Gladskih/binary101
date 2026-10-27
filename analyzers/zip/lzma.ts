import { decompressLzmaWithPropertiesTracked } from "../lzma/decoder.js";
import { crc32 } from "../crc32.js";
import type { ZipCentralDirectoryEntry } from "./types.js";

// APPNOTE 6.3.10, 5.8.8: SDK version (2), properties size (2), properties (usually 5).
// https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
const readProperties = (packed: Uint8Array): number[] => {
  if (packed.byteLength < 9) throw new Error("ZIP LZMA properties header is truncated.");
  if (new DataView(packed.buffer, packed.byteOffset, packed.byteLength).getUint16(2, true) !== 5) {
    throw new Error("ZIP LZMA properties size is unsupported.");
  }
  return [...packed.subarray(4, 9)];
};

export const decompressZipLzma = async (
  packed: Uint8Array, entry: ZipCentralDirectoryEntry
): Promise<Uint8Array> => {
  if (typeof entry.uncompressedSize === "number" &&
      (!Number.isSafeInteger(entry.uncompressedSize) || entry.uncompressedSize < 0)) {
    throw new Error("ZIP LZMA output size is invalid.");
  }
  const result = await decompressLzmaWithPropertiesTracked(
    readProperties(packed), packed.subarray(9), BigInt(entry.uncompressedSize));
  // APPNOTE 5.8.9: general-purpose bit 1 declares an end-of-stream marker.
  // LzmaDec.h: LZMA_STATUS_FINISHED_WITH_MARK = 1.
  if ((entry.flags & 2) !== 0 && result.status !== 1) {
    throw new Error("ZIP LZMA stream is missing its declared end marker.");
  }
  // 7-Zip also checks exact agreement between the EOS flag and completion status:
  // https://github.com/ip7z/7zip/blob/main/CPP/7zip/Compress/LzmaDecoder.h#L95-L100
  if ((entry.flags & 2) === 0 && result.status !== 4) {
    throw new Error("ZIP LZMA stream has an undeclared end marker.");
  }
  if (result.consumedPackedBytes !== packed.byteLength - 9) {
    throw new Error("ZIP LZMA stream has unconsumed input.");
  }
  if (crc32(result.bytes) !== entry.crc32) throw new Error("ZIP LZMA entry CRC-32 mismatch.");
  return result.bytes;
};
