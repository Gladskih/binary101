import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { readDebugPayload } from "./payload-reader.js";
import { parseCodeViewEntry } from "./codeview.js";
import { parseLegacyCodeView } from "./legacy-codeview.js";
import type { PeDebugPayloads } from "./entry-decoders.js";

export const decodeCodeViewPayload = async (
  reader: FileRangeReader, fileSize: number, rvaToOff: RvaToOffset,
  addressOfRawDataRva: number, pointerToRawDataOff: number, dataSize: number,
  addWarning: (message: string) => void
): Promise<PeDebugPayloads> => {
  const signature = dataSize >= 4 ? await readDebugPayload(reader, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, 0, 4) : null;
  if (signature?.byteLength === 4 && /^NB0[25-9]$|^NB11$/.test(String.fromCharCode(
    ...new Uint8Array(signature.buffer, signature.byteOffset, 4)))) {
    const legacyCodeView = await parseLegacyCodeView(reader, fileSize, rvaToOff,
      addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning);
    return legacyCodeView ? { legacyCodeView } : {};
  }
  const codeView = await parseCodeViewEntry(reader, fileSize, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning);
  return codeView ? { codeView } : {};
};
