import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";
import { createDebugPayloadReader } from "./payload-reader.js";

export interface PeSpgoInfo { text: string }

// Type 18 is a UTF-16 C string, distinct from a type-13 POGO table with SPGO magic.
// PE Bliss 2: spgo_debug_directory_base stores packed_utf16_c_string.
// https://github.com/dragon-dreamer/pe_bliss2/blob/e4d56862f2ccd9ed33fa5d4f6c51dfc4d075996f/pe_bliss2/src/debug/debug_directory.cpp#L210
const readSpgoText = async (
  reader: FileRangeReader, addWarning: (message: string) => void
): Promise<string> => {
  const decoder = new TextDecoder("utf-16le", { fatal: true, ignoreBOM: true });
  const parts: string[] = [];
  for (let offset = 0; offset + 2 <= reader.size; offset += 512) {
    const length = Math.min(512, reader.size - offset) & ~1;
    const view = await reader.read(offset, length);
    if (view.byteLength !== length) throw new Error("truncated UTF-16 string");
    for (let index = 0; index < length; index += 2) {
      // A UTF-16 NUL is two zero bytes in either byte order.
      if (view.getUint16(index) !== 0) continue;
      parts.push(decoder.decode(new Uint8Array(view.buffer, view.byteOffset, index)));
      const trailing = reader.size - offset - index - 2;
      if (trailing) addWarning(`SPGO debug entry has ${trailing} trailing bytes after its text.`);
      return parts.join("");
    }
    parts.push(decoder.decode(new Uint8Array(view.buffer, view.byteOffset, length), { stream: true }));
  }
  throw new Error("unterminated or odd-length UTF-16 string");
};

export const parseSpgoInfo = async (
  reader: FileRangeReader, fileSize: number, rvaToOff: RvaToOffset,
  addressOfRawData: number, pointerToRawData: number, dataSize: number,
  addWarning: (message: string) => void
): Promise<PeSpgoInfo | null> => {
  try {
    if (!Number.isSafeInteger(dataSize) || dataSize < 2) {
      addWarning("SPGO debug entry has an invalid size for a UTF-16 string.");
      return null;
    }
    const data = getReadableDebugData("SPGO", fileSize, rvaToOff,
      addressOfRawData, pointerToRawData, dataSize, addWarning);
    if (!data) return null;
    return { text: await readSpgoText(createDebugPayloadReader(reader, rvaToOff,
      addressOfRawData, pointerToRawData, data.size), addWarning) };
  } catch (error) {
    addWarning(`SPGO debug entry could not be decoded as UTF-16: ${String(error)}`);
    return null;
  }
};
