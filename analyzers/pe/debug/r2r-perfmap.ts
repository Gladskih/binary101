"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";

export interface PeR2rPerfMapInfo {
  magic: string;
  signatureBytes: number[];
  version: number;
  path: string;
}

// dotnet/runtime PE-COFF addendum, "R2R PerfMap Debug Directory Entry (type 21)":
// fixed payload is Magic "R2RM", 16-byte signature, DWORD version, then UTF-8 NUL path.
const R2R_PERFMAP_FIXED_SIZE = 24;
const R2R_PERFMAP_MAGIC = 0x4d523252;
const R2R_PERFMAP_OFF_SIGNATURE = 4;
const R2R_PERFMAP_SIGNATURE_SIZE = 16;
const R2R_PERFMAP_OFF_VERSION = 20;
const R2R_PERFMAP_OFF_PATH = 24;
const R2R_PERFMAP_SUPPORTED_VERSION = 1;

const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

const formatMagic = (value: number): string => String.fromCharCode(
  value & 0xff,
  (value >>> 8) & 0xff,
  (value >>> 16) & 0xff,
  (value >>> 24) & 0xff
);

const decodeUtf8Path = (bytes: Uint8Array, addWarning: (message: string) => void): string => {
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    addWarning("R2R_PERFMAP path is not valid UTF-8.");
    return new TextDecoder("utf-8").decode(bytes);
  }
};

export const parseR2rPerfMapInfo = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<PeR2rPerfMapInfo | null> => {
  const dataInfo = getReadableDebugData(
    "R2R_PERFMAP",
    fileSize,
    rvaToOff,
    addressOfRawDataRva,
    pointerToRawDataOff,
    dataSize,
    addWarning
  );
  if (!dataInfo) return null;
  if (dataInfo.size < R2R_PERFMAP_FIXED_SIZE) {
    addWarning("R2R_PERFMAP debug entry is smaller than the fixed header.");
    return null;
  }
  const payload = await reader.readBytes(dataInfo.offset, dataInfo.size);
  if (payload.byteLength < R2R_PERFMAP_FIXED_SIZE) {
    addWarning("R2R_PERFMAP debug entry is truncated.");
    return null;
  }
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const magicValue = view.getUint32(0, true);
  if (magicValue !== R2R_PERFMAP_MAGIC) addWarning("R2R_PERFMAP magic is not R2RM.");
  const pathBytes = payload.slice(R2R_PERFMAP_OFF_PATH);
  const zeroIndex = pathBytes.indexOf(0);
  if (zeroIndex === -1) addWarning("R2R_PERFMAP path is not NUL-terminated within SizeOfData.");
  const version = view.getUint32(R2R_PERFMAP_OFF_VERSION, true);
  if (version !== R2R_PERFMAP_SUPPORTED_VERSION) {
    addWarning(
      `R2R_PERFMAP version ${version} is not the supported version ` +
        `${R2R_PERFMAP_SUPPORTED_VERSION}.`
    );
  }
  const pathEnd = zeroIndex === -1 ? pathBytes.length : zeroIndex;
  return {
    magic: formatMagic(magicValue),
    signatureBytes: [...payload.slice(
      R2R_PERFMAP_OFF_SIGNATURE,
      R2R_PERFMAP_OFF_SIGNATURE + R2R_PERFMAP_SIGNATURE_SIZE
    )],
    version,
    path: decodeUtf8Path(pathBytes.slice(0, pathEnd), addWarning)
  };
};
