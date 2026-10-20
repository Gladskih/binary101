import { readDebugPayload } from "./payload-reader.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";

export interface PeMiscDebugRecord {
  dataType: number;
  length: number;
  unicode: boolean | null;
  text: string;
}
export interface PeMiscDebugInfo { records: PeMiscDebugRecord[]; }

type MiscPayloadReader = (offset: number, size: number) => Promise<DataView>;

const miscTerminator = (bytes: Uint8Array, width: number): number => {
  for (let index = 0; index + width <= bytes.length; index += width) {
    if (bytes[index] === 0 && (width === 1 || bytes[index + 1] === 0)) return index;
  }
  return -1;
};

const warnLegacyMiscText = (
  encoding: string, text: Uint8Array, addWarning: (message: string) => void
): void => {
  if (encoding === "windows-1252" && text.some(value => value >= 128)) {
    addWarning("MISC ANSI code page is not recorded; non-ASCII text is shown as Windows-1252.");
  }
};

const readMiscText = async (
  read: MiscPayloadReader, start: number, size: number,
  encoding: "utf-16le" | "windows-1252", addWarning: (message: string) => void
): Promise<string> => {
  const decoder = new TextDecoder(encoding, { fatal: true, ignoreBOM: true });
  const parts: string[] = [];
  const width = encoding === "utf-16le" ? 2 : 1;
  try {
    for (let offset = 0; offset < size; offset += 64) {
      const count = Math.min(64, size - offset);
      const view = await read(start + offset, count);
      const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      const zero = miscTerminator(bytes, width);
      const text = zero < 0 ? bytes : bytes.subarray(0, zero);
      warnLegacyMiscText(encoding, text, addWarning);
      if (zero >= 0) return parts.join("") + decoder.decode(text);
      parts.push(decoder.decode(text, { stream: true }));
      if (view.byteLength < count) break;
    }
    parts.push(decoder.decode());
  } catch {
    addWarning(`MISC text is not valid ${encoding}.`);
    return parts.join("");
  }
  addWarning("MISC text is not NUL-terminated within its record length.");
  return parts.join("");
};

const validateMiscRecordHeader = (
  view: DataView, size: number, addWarning: (message: string) => void
): void => {
  const dataType = view.getUint32(0, true);
  const length = view.getUint32(4, true);
  const unicode = view.getUint8(8);
  if (length > size) addWarning("MISC debug entry length exceeds SizeOfData.");
  if (length < 12) addWarning("MISC debug entry length is smaller than its header.");
  // Windows SDK IMAGE_DEBUG_MISC.Length is rounded to a four-byte boundary.
  if (length % 4 !== 0) addWarning("MISC record length is not rounded to a 4-byte boundary.");
  if (dataType !== 1) addWarning(`MISC record has unsupported data type ${dataType}; text not decoded.`);
  if (unicode > 1) addWarning("MISC Unicode flag is neither 0 nor 1; text not decoded.");
  if (view.getUint8(9) | view.getUint8(10) | view.getUint8(11)) {
    addWarning("MISC reserved bytes are non-zero.");
  }
};

const readMiscRecord = async (
  read: MiscPayloadReader, offset: number, size: number, addWarning: (message: string) => void
): Promise<PeMiscDebugRecord | null> => {
  // IMAGE_DEBUG_MISC: DWORD DataType, DWORD Length, BYTE Unicode, BYTE Reserved[3], Data[].
  // Microsoft's locator advances by Length, so one debug payload may contain multiple records.
  // https://github.com/microsoft/microsoft-pdb/blob/master/PDB/dbi/locator.cpp#L1610
  const view = await read(offset, 12);
  if (view.byteLength < 12) {
    addWarning("MISC record header is truncated.");
    return null;
  }
  validateMiscRecordHeader(view, size, addWarning);
  const dataType = view.getUint32(0, true);
  const length = view.getUint32(4, true);
  const unicode = view.getUint8(8);
  return { dataType, length, unicode: unicode <= 1 ? unicode === 1 : null,
    text: length >= 12 && dataType === 1 && unicode <= 1
      ? await readMiscText(read, offset + 12, Math.min(length, size) - 12,
        unicode === 1 ? "utf-16le" : "windows-1252", addWarning) : "" };
};

export const parseMiscDebugInfo = async (
  reader: FileRangeReader, fileSize: number, rvaToOff: RvaToOffset,
  addressOfRawDataRva: number, pointerToRawDataOff: number, dataSize: number,
  addWarning: (message: string) => void
): Promise<PeMiscDebugInfo | null> => {
  const dataInfo = getReadableDebugData("MISC", fileSize, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning);
  if (!dataInfo) return null;
  if (dataInfo.size < 12) {
    addWarning("MISC debug entry is smaller than IMAGE_DEBUG_MISC.");
    return null;
  }
  const read: MiscPayloadReader = (offset, size) => readDebugPayload(reader, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, offset, size);
  const records: PeMiscDebugRecord[] = [];
  let offset = 0;
  while (offset < dataInfo.size) {
    if (dataInfo.size - offset < 12) {
      addWarning("MISC payload has trailing bytes after complete records.");
      break;
    }
    const record = await readMiscRecord(read, offset, dataInfo.size - offset, addWarning);
    if (!record) break;
    records.push(record);
    if (record.length < 12) break;
    offset += record.length;
  }
  return { records };
};
