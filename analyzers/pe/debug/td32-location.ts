import type { FileRangeReader } from "../../file-range-reader.js";

export interface Td32Location { offset: number; size: number; }
const isSignature = (value: number): boolean => value === 0x39304246 || value === 0x41304246;
const isFileRange = (fileSize: number, offset: number, size: number): boolean =>
  Number.isSafeInteger(offset) && Number.isSafeInteger(size) &&
  offset >= 0 && size >= 0 && offset <= fileSize - size;

// Container anchors, without an arbitrary signature scan:
// https://github.com/csm101/delphi-visual-studio-code-debugger/blob/580b258063a37e6e6bd93a9a7593e0b8cc8a9d06/DebuggerCore/TD32FileReader.pas
// FindTD32Header / FindAppendedDebugBlob: trailer magic + backward distance,
// checked against the corresponding header. A leading header is also an anchor.
const trailerLocation = async (reader: FileRangeReader, offset: number, size: number,
  warn: (message: string) => void): Promise<Td32Location | null> => {
  const footer = await reader.read(offset + size - 8, 8);
  if (footer.byteLength < 8) { warn("TD32 trailer read is truncated."); return null; }
  const signature = footer.getUint32(0, true);
  if (!isSignature(signature)) return null;
  const distance = footer.getUint32(4, true);
  if (distance >= 16 && distance <= size) {
    const start = offset + size - distance;
    const header = await reader.read(start, 4);
    if (header.byteLength === 4 && header.getUint32(0, true) === signature) {
      return { offset: start, size: distance };
    }
  }
  warn("TD32 trailer has an invalid backward distance or mismatched header.");
  return null;
};

export const findTd32Location = async (reader: FileRangeReader, offset: number, size: number,
  warn: (message: string) => void): Promise<Td32Location | null> => {
  if (!isFileRange(reader.size, offset, size)) {
    warn("TD32 candidate range exceeds file bounds.");
    return null;
  }
  if (size < 8) return null;
  try {
    const trailer = await trailerLocation(reader, offset, size, warn);
    if (trailer) return trailer;
    const header = await reader.read(offset, 4);
    return header.byteLength === 4 && isSignature(header.getUint32(0, true)) ? { offset, size } : null;
  } catch (error) { warn(`TD32 location read failed: ${String(error)}`); return null; }
};
