import { createFileRangeReader, DEFAULT_FILE_READ_WINDOW_BYTES } from "../../file-range-reader.js";
import type { FileRangeReader } from "../../file-range-reader.js";

export const inflateEmbeddedDebugImage = async (
  compressed: Pick<FileRangeReader, "size" | "readBytes">, expectedSize: number
): Promise<FileRangeReader> => {
  // Raw Deflate, not zlib: Embedded Portable PDB in the .NET PE/COFF addendum.
  // Stream input and check emitted bytes before retaining each chunk. Never allocate
  // the untrusted UncompressedSize or use a heuristic expansion-ratio cutoff.
  // https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md
  let offset = 0;
  const stream = new ReadableStream<Uint8Array<ArrayBuffer>>({
    async pull(controller) {
      if (offset === compressed.size) return controller.close();
      const size = Math.min(DEFAULT_FILE_READ_WINDOW_BYTES, compressed.size - offset);
      const bytes = await compressed.readBytes(offset, size);
      if (bytes.length !== size) throw new Error("compressed debug stream is truncated");
      offset += size;
      controller.enqueue(new Uint8Array(bytes));
    }
  }).pipeThrough(new DecompressionStream("deflate-raw"));
  const reader = stream.getReader();
  const chunks: BlobPart[] = [];
  let total = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      total += chunk.value.length;
      if (total > expectedSize) throw new Error("decompressed debug image exceeds declared size");
      chunks.push(new Uint8Array(chunk.value).buffer);
    }
    if (total !== expectedSize) throw new Error("decompressed debug image size does not match declared size");
    return createFileRangeReader(new File(chunks, "embedded-debug-data"), 0, total);
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
};
