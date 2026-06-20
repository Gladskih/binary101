"use strict";

import { MockFile } from "./mock-file.js";

class ChunkedStreamBlob extends Blob {
  readonly #bytes: Uint8Array<ArrayBuffer>;
  readonly #chunkSize: number;
  readonly #onStream: () => void;

  constructor(bytes: Uint8Array, type: string, chunkSize: number, onStream: () => void) {
    const copy = new Uint8Array(bytes);
    super([copy.buffer], { type });
    this.#bytes = copy;
    this.#chunkSize = chunkSize;
    this.#onStream = onStream;
  }

  override stream(): ReadableStream<Uint8Array<ArrayBuffer>> {
    this.#onStream();
    let offset = 0;
    return new ReadableStream<Uint8Array<ArrayBuffer>>({
      type: "bytes",
      pull: controller => {
        if (offset >= this.#bytes.length) {
          controller.close();
          return;
        }
        const end = Math.min(this.#bytes.length, offset + this.#chunkSize);
        controller.enqueue(this.#bytes.slice(offset, end));
        offset = end;
      }
    });
  }
}

const normalizeIndex = (value: number | undefined, size: number, fallback: number): number => {
  if (value == null) return fallback;
  const integer = Math.trunc(value);
  return integer < 0 ? Math.max(size + integer, 0) : Math.min(integer, size);
};

const createChunkedStreamFile = (
  source: MockFile,
  chunkSize: number
): { file: MockFile; streamSizes: number[] } => {
  const streamSizes: number[] = [];
  const safeChunkSize = Math.max(Uint8Array.BYTES_PER_ELEMENT, Math.floor(chunkSize));
  class TrackedChunkedStreamFile extends MockFile {
    override slice(start?: number, end?: number, contentType?: string): Blob {
      const safeStart = normalizeIndex(start, this.size, 0);
      const safeEnd = Math.max(safeStart, normalizeIndex(end, this.size, this.size));
      const bytes = this.data.slice(safeStart, safeEnd);
      return new ChunkedStreamBlob(bytes, contentType ?? "", safeChunkSize, () => {
        streamSizes.push(bytes.length);
      });
    }
  }
  return {
    file: new TrackedChunkedStreamFile(source.data, source.name, source.type),
    streamSizes
  };
};

export const createOneByteChunkedStreamFile = (
  source: MockFile
): { file: MockFile; streamSizes: number[] } =>
  createChunkedStreamFile(source, Uint8Array.BYTES_PER_ELEMENT);
