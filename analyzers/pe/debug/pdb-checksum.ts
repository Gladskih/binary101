import { readDebugPayloadBytes } from "./payload-reader.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData } from "./data.js";

export interface PePdbChecksumInfo {
  algorithmName: string;
  checksumBytes: number[];
}

// Supported names are case-sensitive. Sizes are mandated by the algorithms, not display caps.
// https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md#pdb-checksum-debug-directory-entry-type-19
const PDB_CHECKSUM_SIZES: Readonly<Record<string, number>> = { SHA1: 20, SHA256: 32, SHA384: 48, SHA512: 64 };

const decodeAlgorithm = (bytes: Uint8Array, addWarning: (message: string) => void): string | null => {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    addWarning("PDB checksum algorithm name is not valid UTF-8.");
    return null;
  }
};

export const parsePdbChecksumInfo = async (
  reader: FileRangeReader, fileSize: number, rvaToOff: RvaToOffset,
  addressOfRawDataRva: number, pointerToRawDataOff: number, dataSize: number,
  addWarning: (message: string) => void
): Promise<PePdbChecksumInfo | null> => {
  const dataInfo = getReadableDebugData("PDB checksum", fileSize, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, addWarning);
  if (!dataInfo) return null;
  // Read only enough to recognize one of the supported names plus its NUL terminator.
  // Unknown algorithms remain undecoded instead of materializing an unbounded opaque digest.
  const bytes = await readDebugPayloadBytes(reader, rvaToOff, addressOfRawDataRva, pointerToRawDataOff,
    0, Math.min(dataInfo.size, Math.max(...Object.keys(PDB_CHECKSUM_SIZES).map(name => name.length)) + 1));
  const terminator = bytes.indexOf(0);
  if (terminator === -1) {
    addWarning(bytes.length === dataInfo.size
      ? "PDB checksum algorithm name is not NUL-terminated within SizeOfData."
      : "PDB checksum algorithm is not supported; payload not decoded.");
    return null;
  }
  const algorithmName = decodeAlgorithm(bytes.subarray(0, terminator), addWarning);
  if (algorithmName == null) return null;
  if (!algorithmName) addWarning("PDB checksum algorithm name is empty.");
  const expected = PDB_CHECKSUM_SIZES[algorithmName];
  if (expected == null) {
    addWarning("PDB checksum algorithm is not supported; payload not decoded.");
    return null;
  }
  const available = dataInfo.size - terminator - 1;
  if (available !== expected) {
    addWarning(`PDB checksum ${algorithmName} requires ${expected} bytes; the stored digest length differs.`);
  }
  return { algorithmName, checksumBytes: [...await readDebugPayloadBytes(reader, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, terminator + 1, Math.min(expected, available))] };
};