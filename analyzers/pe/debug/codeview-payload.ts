import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { readDebugPayload } from "./payload-reader.js";
import { parseCodeViewEntry } from "./codeview.js";
import { parseLegacyCodeView } from "./legacy-codeview.js";
import { parseHll } from "./hll.js";
import type { PeDebugPayloads } from "./entry-decoders.js";

export const decodeCodeViewPayload = async (
  reader: FileRangeReader, fileSize: number, rvaToOff: RvaToOffset,
  addressOfRawDataRva: number, pointerToRawDataOff: number, dataSize: number,
  addWarning: (message: string) => void
): Promise<PeDebugPayloads> => {
  const signature = dataSize >= 4 ? await readDebugPayload(reader, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, 0, 4) : null;
  const name = signature?.byteLength === 4 ? String.fromCharCode(
    ...new Uint8Array(signature.buffer, signature.byteOffset, 4)) : "";
  if (/^NB0[245-9]$|^NB11$/.test(name)) {
    const parse = name === "NB04" ? parseHll : parseLegacyCodeView;
    const legacyCodeView = await parse(reader, fileSize, rvaToOff,
      addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning);
    return legacyCodeView ? { legacyCodeView } : {};
  }
  const codeView = await parseCodeViewEntry(reader, fileSize, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning);
  return codeView ? { codeView } : {};
};
