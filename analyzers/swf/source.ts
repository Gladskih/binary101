import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";

const isStreamRange = (offset: number, length: number, size: number): boolean =>
  Number.isSafeInteger(offset) && Number.isSafeInteger(length) && offset >= 8 && offset <= size && length >= 0;

// Forward-only uncompressed CWS address space: one requested window and one stream chunk.
// Adobe SWF v19, chapter 2: zlib covers bytes after the fixed eight-byte header.
// https://open-flash.github.io/mirrors/swf-spec-19.pdf
class CwsBodyReader implements FileRangeReader {
  readonly size: number;
  readonly #input: ReadableStreamDefaultReader<Uint8Array<ArrayBuffer>>;
  #chunk: Uint8Array = new Uint8Array();
  #chunkIndex = 0;
  #loaded = 8;
  #cursor = 8;
  #cacheOffset = 8;
  #cache: Uint8Array = new Uint8Array();

  constructor(input: ReadableStream<Uint8Array<ArrayBuffer>>, fileLength: number) {
    this.size = fileLength;
    this.#input = input.pipeThrough(new DecompressionStream("deflate")).getReader();
  }

  async #ensureChunk(): Promise<boolean> {
    if (this.#chunkIndex < this.#chunk.length) return true;
    const next = await this.#input.read();
    if (next.done) {
      if (this.#loaded !== this.size) throw new Error("SWF decompressed length differs from FileLength.");
      return false;
    }
    this.#loaded += next.value.length;
    if (this.#loaded > this.size) throw new Error("SWF decompression exceeds FileLength.");
    this.#chunk = next.value;
    this.#chunkIndex = 0;
    return true;
  }

  async #skipTo(offset: number): Promise<void> {
    while (this.#cursor < offset) {
      if (!await this.#ensureChunk()) throw new Error("SWF compressed body is truncated.");
      const length = Math.min(offset - this.#cursor, this.#chunk.length - this.#chunkIndex);
      this.#chunkIndex += length;
      this.#cursor += length;
    }
  }

  async #fill(bytes: Uint8Array, prefixLength: number): Promise<void> {
    let filled = prefixLength;
    while (filled < bytes.length) {
      if (!await this.#ensureChunk()) throw new Error("SWF compressed body is truncated.");
      const take = Math.min(bytes.length - filled, this.#chunk.length - this.#chunkIndex);
      bytes.set(this.#chunk.subarray(this.#chunkIndex, this.#chunkIndex + take), filled);
      filled += take;
      this.#chunkIndex += take;
      this.#cursor += take;
    }
  }

  async read(offset: number, length: number): Promise<DataView> {
    if (!isStreamRange(offset, length, this.size)) throw new Error("SWF stream read is out of bounds.");
    const size = Math.min(length, this.size - offset);
    if (offset >= this.#cacheOffset && offset + size <= this.#cacheOffset + this.#cache.length) {
      return new DataView(this.#cache.buffer, this.#cache.byteOffset + offset - this.#cacheOffset, size);
    }
    const bytes = new Uint8Array(size);
    let filled = 0;
    if (offset < this.#cursor) {
      if (offset < this.#cacheOffset) throw new Error("SWF stream cannot seek backwards outside its window.");
      filled = Math.min(size, this.#cursor - offset);
      bytes.set(this.#cache.subarray(offset - this.#cacheOffset, offset - this.#cacheOffset + filled));
    }
    await this.#skipTo(offset);
    await this.#fill(bytes, filled);
    this.#cache = bytes;
    this.#cacheOffset = offset;
    return new DataView(bytes.buffer);
  }

  async readBytes(offset: number, length: number): Promise<Uint8Array> {
    const view = await this.read(offset, length);
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }

  async finish(): Promise<void> {
    await this.#skipTo(this.size);
    if (await this.#ensureChunk()) throw new Error("SWF decompression exceeds FileLength.");
  }

  async close(): Promise<void> {
    await this.#input.cancel().catch(() => undefined);
    this.#input.releaseLock();
  }
}

export const openCwsBody = (file: File, start: number, end: number, fileLength: number) =>
  new CwsBodyReader(file.slice(start + 8, end).stream(), fileLength);

export const openCwsPrefix = (file: File, start: number, end: number, fileLength: number) => {
  const source = createFileRangeReader(file, start + 8, end - start - 8);
  let offset = 0;
  let closed = false;
  // Feed small input chunks for header inspection. A native Blob chunk can contain the
  // entire compressed form of a large zero-filled movie; decoding that just for its RECT
  // costs unnecessary CPU and buffering. The range reader still coalesces physical I/O.
  const input = new ReadableStream<Uint8Array<ArrayBuffer>>({
    async pull(controller) {
      if (offset === source.size) return controller.close();
      const bytes = await source.readBytes(offset, Math.min(64, source.size - offset));
      if (closed) return;
      offset += bytes.length;
      if (!bytes.length) throw new Error("SWF compressed prefix is truncated.");
      controller.enqueue(new Uint8Array(bytes));
    },
    cancel() { closed = true; }
  });
  return new CwsBodyReader(input, fileLength);
};
