import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";
import { readDebugPayload } from "./payload-reader.js";

export interface PeMpxInfo {
  flags: number;
  unknown1: number;
  unknown2: number;
  unknown3: number;
}

// Publicly reversed JRBP layout and flags, PE Bliss 2 (image_debug_mpx).
// https://github.com/dragon-dreamer/pe_bliss2/blob/e4d56862f2ccd9ed33fa5d4f6c51dfc4d075996f/pe_bliss2/include/pe_bliss2/detail/debug/image_debug_directory.h#L295
const decodeMpx = (view: DataView, addWarning: (message: string) => void): PeMpxInfo | null => {
  if (view.byteLength < 20) {
    addWarning("MPX debug entry is truncated before its 20-byte header.");
    return null;
  }
  if (view.getUint32(0, true) !== 0x5042524a) {
    addWarning("MPX debug entry has an unrecognized signature; expected JRBP.");
    return null;
  }
  const flags = view.getUint32(8, true);
  const unknown = (flags & ~7) >>> 0;
  if (unknown) addWarning(`MPX debug entry has unknown flag bits 0x${unknown.toString(16)}.`);
  return { flags, unknown1: view.getUint32(4, true),
    unknown2: view.getUint32(12, true), unknown3: view.getUint32(16, true) };
};

export const parseMpxInfo = async (
  reader: FileRangeReader, fileSize: number, rvaToOff: RvaToOffset,
  addressOfRawData: number, pointerToRawData: number, dataSize: number,
  addWarning: (message: string) => void
): Promise<PeMpxInfo | null> => {
  try {
    if (!Number.isSafeInteger(dataSize) || dataSize < 20) {
      addWarning("MPX debug entry is smaller than its 20-byte header or has an invalid size.");
      return null;
    }
    const data = getReadableDebugData("MPX", fileSize, rvaToOff,
      addressOfRawData, pointerToRawData, dataSize, addWarning);
    if (!data) return null;
    if (dataSize > 20) addWarning("MPX debug entry has trailing bytes after its known header.");
    return decodeMpx(await readDebugPayload(reader, rvaToOff,
      addressOfRawData, pointerToRawData, 0, Math.min(data.size, 20)), addWarning);
  } catch (error) {
    addWarning(`MPX debug entry could not be decoded: ${String(error)}`);
    return null;
  }
};
