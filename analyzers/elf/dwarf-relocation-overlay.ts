import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfDwarfPatch } from "./dwarf-relocation-types.js";

// Overlay only relocated fields; all original file reads retain the shared bounded reader.
export const elfDwarfRelocationOverlay = (reader: FileRangeReader,
  patches: ElfDwarfPatch[]): FileRangeReader => {
  const sorted = [...patches].sort((left, right) => left.offset - right.offset);
  const read = async (offset: number, size: number): Promise<DataView> => {
    const view = await reader.read(offset, size);
    const first = firstIntersecting(sorted, offset);
    if (!sorted[first] || sorted[first]!.offset >= offset + view.byteLength) return view;
    const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength).slice();
    for (let index = first; index < sorted.length && sorted[index]!.offset < offset + bytes.length; index += 1) {
      const patch = sorted[index]!;
      const start = Math.max(offset, patch.offset);
      const end = Math.min(offset + bytes.length, patch.offset + patch.bytes.length);
      bytes.set(patch.bytes.subarray(start - patch.offset, end - patch.offset), start - offset);
    }
    return new DataView(bytes.buffer);
  };
  return { size: reader.size, read, readBytes: async (offset, size) => {
    const view = await read(offset, size);
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  } };
};

const firstIntersecting = (patches: ElfDwarfPatch[], offset: number): number => {
  let low = 0;
  let high = patches.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (patches[middle]!.offset + patches[middle]!.bytes.length <= offset) low = middle + 1;
    else high = middle;
  }
  return low;
};
