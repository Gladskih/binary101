import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";
import { contiguousRvaOffset } from "../rva-mapping.js";

export interface CodeViewLocation { offset: number; size: number; }
const isSignature = (value: number): boolean => value === 0x3430424e || value === 0x3230424e;
const isRange = (fileSize: number, offset: number, size: number): boolean =>
  Number.isSafeInteger(offset) && Number.isSafeInteger(size) && offset >= 0 && size >= 0 && size <= fileSize - offset;

// Open Watcom HLL loader: header at a section/overlay boundary, or matching
// terminal trailer with a backward distance. No arbitrary signature scanning.
// IBM linkers may place the NB04 header directly at the PE DEBUG directory RVA.
// https://github.com/open-watcom/open-watcom-v2/blob/065b3083b9f06919c871c67ce608e3b29674ffce/bld/dip/hllcv/c/hllld.c
const trailerLocation = async (reader: FileRangeReader, offset: number, size: number,
  warn: (message: string) => void): Promise<CodeViewLocation | null> => {
    if (size < 16) return null; // A header alone cannot also be a terminal trailer.
    const trailer = await reader.read(offset + size - 8, 8);
    if (trailer.byteLength !== 8) throw new Error("CodeView trailer read is truncated.");
    if (isSignature(trailer.getUint32(0, true))) {
      const distance = trailer.getUint32(4, true);
      if (distance >= 16 && distance <= size) {
        const start = offset + size - distance;
        const header = await reader.read(start, 4);
        if (header.byteLength === 4 && header.getUint32(0, true) === trailer.getUint32(0, true)) {
          return { offset: start, size: distance };
        }
      }
      warn("CodeView trailer has an invalid backward distance or mismatched header.");
    }
    return null;
};

export const findCodeViewLocation = async (reader: FileRangeReader, offset: number, size: number,
  warn: (message: string) => void): Promise<CodeViewLocation | null> => {
  if (!isRange(reader.size, offset, size)) { warn("CodeView candidate range exceeds file bounds."); return null; }
  if (size < 8) return null;
  try {
    const trailer = await trailerLocation(reader, offset, size, warn);
    if (trailer) return trailer;
    const header = await reader.read(offset, 4);
    return header.byteLength === 4 && isSignature(header.getUint32(0, true)) ? { offset, size } : null;
  } catch (error) { warn(`CodeView location read failed: ${String(error)}`); return null; }
};

export const directHllDirectory = async (reader: FileRangeReader, directory: PeDataDirectory,
  rvaToOff: RvaToOffset, warn: (message: string) => void): Promise<CodeViewLocation | null> => {
  if (directory.size < 8) return null;
  const offset = contiguousRvaOffset(rvaToOff, directory.rva, directory.size, reader.size);
  if (offset == null) return null;
  try {
    const header = await reader.read(offset, 4);
    return header.byteLength === 4 && header.getUint32(0, true) === 0x3430424e
      ? { offset, size: directory.size } : null;
  } catch (error) { warn(`HLL directory header read failed: ${String(error)}`); return null; }
};
