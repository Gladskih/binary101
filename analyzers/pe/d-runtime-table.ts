import { DEFAULT_FILE_READ_WINDOW_BYTES, type FileRangeReader } from "../file-range-reader.js";
import { readDPointer } from "../d-runtime/fields.js";
import type { DRuntimeImage } from "../d-runtime/types.js";
import type { PeSection } from "./types.js";

function* pointersInView(view: DataView, image: DRuntimeImage): Generator<bigint> {
  for (let offset = 0; offset + image.pointerSize <= view.byteLength; offset += image.pointerSize) {
    const address = readDPointer(image, view, offset);
    // druntime permits NULL linker padding; skip it synchronously, without per-slot awaits.
    if (address !== 0n) yield address;
  }
}

async function* streamPointers(file: Blob, offset: number, size: number,
  image: DRuntimeImage, warnings: string[]): AsyncGenerator<bigint> {
  const reader = file.slice(offset, offset + size).stream().getReader();
  let consumed = 0;
  let carry = new Uint8Array(0);
  try {
    while (consumed < size) {
      const chunk = await reader.read();
      if (chunk.done || !chunk.value.byteLength) break;
      const bytes = carry.byteLength
        ? new Uint8Array(carry.byteLength + chunk.value.byteLength) : chunk.value;
      if (carry.byteLength) {
        bytes.set(carry);
        bytes.set(chunk.value, carry.byteLength);
      }
      consumed += chunk.value.byteLength;
      yield* pointersInView(new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength), image);
      // Preserve only a split pointer, not the scanned table, between stream chunks.
      carry = bytes.slice(bytes.byteLength - bytes.byteLength % image.pointerSize);
    }
    if (consumed !== size || carry.byteLength) {
      warnings.push("D .minfo pointer table is truncated or has an incomplete pointer.");
    }
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
}

export async function* readDModuleTable(file: Blob, reader: FileRangeReader,
  section: PeSection, image: DRuntimeImage, warnings: string[]): AsyncGenerator<bigint> {
  const size = Math.min(section.sizeOfRawData, section.virtualSize || section.sizeOfRawData);
  if (!Number.isSafeInteger(section.pointerToRawData) || section.pointerToRawData < 0 ||
    !Number.isSafeInteger(size) || size < 0) {
    warnings.push("D .minfo has an invalid file range.");
    return;
  }
  // Small tables reuse cached sparse reads; deep sequential walks use a file stream.
  // The window controls temporary I/O, never the number of modules analyzed.
  if (size > DEFAULT_FILE_READ_WINDOW_BYTES) {
    yield* streamPointers(file, section.pointerToRawData, size, image, warnings);
    return;
  }
  const view = await reader.read(section.pointerToRawData, size);
  yield* pointersInView(view, image);
  if (view.byteLength !== size || size % image.pointerSize !== 0) {
    warnings.push("D .minfo pointer table is truncated or has an incomplete pointer.");
  }
}
