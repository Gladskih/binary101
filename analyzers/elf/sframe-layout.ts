import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfSFrame, ElfSFrameFunction, ElfSFrameHeader } from "./sframe-types.js";

// GNU Binutils SFrame specification §§2.1–2.3 and Appendix A.
// https://sourceware.org/binutils/docs-2.46/sframe-spec.html
export const SFRAME_HEADER_SIZE = 28;
export const SFRAME_START_PCREL = 0x4;
export const SFRAME_DESCRIPTOR_SIZES: Readonly<Record<number, number>> = {
  1: 17, 2: 20, 3: 16
};

export const sframeFunctionAddress = (table: ElfSFrame, entry: ElfSFrameFunction): bigint | null => {
  if (table.address == null || !table.preamble) return null;
  // In v2/v3 the flag makes the start offset relative to its own field.
  const { version, flags } = table.preamble;
  const fieldOffset = version >= 2 && (flags & SFRAME_START_PCREL) ? BigInt(entry.offset) : 0n;
  const address = table.address + fieldOffset + entry.startOffset;
  return BigInt.asUintN(64, address) === address ? address : null;
};

const decodeHeader = (view: DataView, little: boolean): ElfSFrameHeader => ({
  abi: view.getUint8(4), fixedFpOffset: view.getInt8(5), fixedRaOffset: view.getInt8(6),
  auxSize: view.getUint8(7), functionCount: view.getUint32(8, little),
  rowCount: view.getUint32(12, little), rowBytes: view.getUint32(16, little),
  functionOffset: view.getUint32(20, little), rowOffset: view.getUint32(24, little)
});

export const readSFrameHeader = async (
  reader: FileRangeReader, little: boolean, table: ElfSFrame
): Promise<void> => {
  const view = await reader.read(0, SFRAME_HEADER_SIZE);
  if (view.byteLength < 4) {
    table.issues.push("Truncated SFrame preamble.");
  } else if (view.getUint16(0, little) !== 0xdee2) {
    table.issues.push("Invalid SFrame magic in ELF byte order.");
  } else {
    const version = view.getUint8(2);
    const flags = view.getUint8(3);
    table.preamble = { version, flags };
    if (!SFRAME_DESCRIPTOR_SIZES[version]) table.issues.push(`Unsupported SFrame version ${version}.`);
    else if (view.byteLength < SFRAME_HEADER_SIZE) table.issues.push("Truncated SFrame header.");
    else table.header = decodeHeader(view, little);
  }
};

export const readSFrameDescriptor = async (
  reader: FileRangeReader, little: boolean, offset: number, version: number
): Promise<ElfSFrameFunction | null> => {
  const size = SFRAME_DESCRIPTOR_SIZES[version]!;
  const view = await reader.read(offset, size);
  if (view.byteLength !== size) return null;
  if (version === 3) {
    return { offset, startOffset: view.getBigInt64(0, little), size: view.getUint32(8, little),
      rowOffset: view.getUint32(12, little), issues: [] };
  }
  return {
    offset, startOffset: BigInt(view.getInt32(0, little)), size: view.getUint32(4, little),
    rowOffset: view.getUint32(8, little), issues: [],
    attributes: {
      rowCount: view.getUint32(12, little), info: view.getUint8(16),
      ...(version === 2 ? { repeatSize: view.getUint8(17) } : {})
    }
  };
};
