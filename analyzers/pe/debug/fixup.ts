import type { FileRangeReader } from "../../file-range-reader.js";
import { DEFAULT_FILE_READ_WINDOW_BYTES } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";
import { readDebugPayload } from "./payload-reader.js";

export interface PeFixupRecord { type: number; extra: number; rva: number; targetRva: number; }
export interface PeFixupInfo { records: PeFixupRecord[]; }

// Microsoft cvdump's XFIXUP: WORD type, WORD extra, DWORD RVA, DWORD target RVA.
// Extra remains uninterpreted; the published structure does not specify its bits.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/cvdump/cvdump.h#L232
const readFixup = (view: DataView, offset: number): PeFixupRecord => ({
  type: view.getUint16(offset, true), extra: view.getUint16(offset + 2, true),
  rva: view.getUint32(offset + 4, true), targetRva: view.getUint32(offset + 8, true)
});

export const parseFixupInfo = async (
  reader: FileRangeReader, fileSize: number, rvaToOff: RvaToOffset,
  addressOfRawDataRva: number, pointerToRawDataOff: number, dataSize: number,
  addWarning: (message: string) => void
): Promise<PeFixupInfo | null> => {
  if (dataSize === 0) return { records: [] };
  const location = getReadableDebugData("FIXUP", fileSize, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning);
  if (!location) return null;
  if (location.size < 12) {
    addWarning("FIXUP debug payload is smaller than a 12-byte XFIXUP record.");
    return null;
  }
  if (location.size % 12) addWarning("Debug data ends with a partial FIXUP record.");
  const size = location.size - location.size % 12;
  const windowSize = Math.floor(DEFAULT_FILE_READ_WINDOW_BYTES / 12) * 12;
  const records: PeFixupRecord[] = [];
  for (let offset = 0; offset < size; offset += windowSize) {
    const count = Math.min(windowSize, size - offset);
    const view = await readDebugPayload(reader, rvaToOff, addressOfRawDataRva, pointerToRawDataOff, offset, count);
    for (let cursor = 0; cursor + 12 <= view.byteLength; cursor += 12) records.push(readFixup(view, cursor));
    if (view.byteLength < count) { addWarning("FIXUP debug payload is truncated."); break; }
  }
  return { records };
};
