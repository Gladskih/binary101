import { readGuid } from "./reader.js";
import type { ResourceTypeLibrarySegmentPreview } from "../resources/preview/types.js";

// Packed SLTG_Header, SLTG_BlkEntry, SLTG_Magic, SLTG_Index and SLTG_Pad9.
// https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.h
export const readSltgBlocks = (
  data: Uint8Array, issues: string[]
): ResourceTypeLibrarySegmentPreview[] => {
  if (data.length < 36) {
    issues.push("TYPELIB SLTG header is truncated.");
    return [];
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = view.getUint16(4, true);
  if (count < 2) {
    issues.push("TYPELIB SLTG block count is invalid.");
    return [];
  }
  const magic = 36 + (count - 1) * 8;
  const position = magic + 13 + (count - 2) * 11 + 9;
  if (position > data.length) {
    issues.push("TYPELIB SLTG block directory is truncated.");
    return [];
  }
  if (new TextDecoder().decode(data.subarray(magic, magic + 13)) !== "\x01CompObj\0dir\0") {
    issues.push("TYPELIB SLTG directory magic is invalid.");
    return [];
  }
  return readBlockChain(view, position, count, data.length, issues);
};

const readBlockChain = (
  view: DataView, initialPosition: number, count: number, dataLength: number, issues: string[]
): ResourceTypeLibrarySegmentPreview[] => {
  const result: ResourceTypeLibrarySegmentPreview[] = [];
  let position = initialPosition;
  const seen = new Set<number>();
  let index = view.getUint16(10, true);
  while (index !== 0) {
    if (seen.has(index)) {
      issues.push("TYPELIB SLTG block chain has an invalid index or cycle.");
      break;
    }
    seen.add(index);
    if (index >= count) {
      issues.push("TYPELIB SLTG block index is outside the directory.");
      break;
    }
    const entry = 36 + (index - 1) * 8;
    const length = view.getUint32(entry, true);
    if (length > dataLength - position) {
      issues.push("TYPELIB SLTG block is truncated.");
      break;
    }
    result.push({ name: `SLTG block ${index}`, offset: position, length });
    position += length;
    index = view.getUint16(entry + 6, true);
  }
  if (seen.size !== count - 1) issues.push("TYPELIB SLTG block chain does not cover all blocks.");
  return result;
};

export const sltgHeaderFields = (data: Uint8Array): Array<{ label: string; value: string }> => {
  if (data.length < 36) return [];
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return [
    { label: "Blocks (including directory)", value: String(view.getUint16(4, true)) },
    { label: "First block index", value: String(view.getUint16(10, true)) },
    { label: "Format GUID", value: readGuid(view, 12)! }
  ];
};
