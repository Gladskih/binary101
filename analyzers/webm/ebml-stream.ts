"use strict";

import { DEFAULT_FILE_READ_WINDOW_BYTES } from "../file-range-reader.js";
import { MAX_ELEMENT_HEADER } from "./constants.js";
import { readElementHeader } from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import type { Issues } from "./types.js";

const EMPTY_BYTES: Uint8Array<ArrayBufferLike> = new Uint8Array(0);

export class EbmlStreamReader {
  readonly #reader: ReadableStreamBYOBReader;
  readonly #endOffset: number;
  #bytes: Uint8Array<ArrayBufferLike>;
  #byteOffset: number;
  #currentOffset: number;
  #done: boolean;
  #released: boolean;

  constructor(stream: ReadableStream<Uint8Array>, startOffset: number, endOffset: number) {
    // File API requires Blob streams to support byte reading, so a BYOB reader
    // keeps the incremental parser bounded even if an implementation would
    // otherwise emit a very large chunk.
    // https://w3c.github.io/FileAPI/#blob-get-stream
    this.#reader = stream.getReader({ mode: "byob" });
    this.#endOffset = Math.max(startOffset, endOffset);
    this.#bytes = EMPTY_BYTES;
    this.#byteOffset = 0;
    this.#currentOffset = startOffset;
    this.#done = false;
    this.#released = false;
  }

  get offset(): number {
    return this.#currentOffset;
  }

  async readElementHeader(endOffset: number, issues: Issues): Promise<EbmlElementHeader | null> {
    const available = Math.max(0, Math.min(endOffset, this.#endOffset) - this.#currentOffset);
    if (available === 0) return null;
    await this.#fill(Math.min(MAX_ELEMENT_HEADER, available));
    const visible = Math.min(this.#availableBytes(), available);
    if (visible === 0) {
      issues.push(`Unexpected end of stream at ${this.#currentOffset}.`);
      return null;
    }
    const view = new DataView(
      this.#bytes.buffer,
      this.#bytes.byteOffset + this.#byteOffset,
      visible
    );
    const header = readElementHeader(view, 0, this.#currentOffset, issues);
    if (!header) return null;
    this.#consume(header.headerSize);
    return header;
  }

  async readBytes(size: number): Promise<Uint8Array> {
    const requested = this.#clampSize(size);
    if (requested === 0) return EMPTY_BYTES;
    await this.#fill(requested);
    const length = Math.min(requested, this.#availableBytes());
    const bytes = this.#bytes.subarray(this.#byteOffset, this.#byteOffset + length);
    this.#consume(length);
    return bytes;
  }

  async skip(size: number): Promise<number> {
    let remaining = this.#clampSize(size);
    const requested = remaining;
    while (remaining > 0) {
      if (this.#availableBytes() === 0) await this.#fill(Uint8Array.BYTES_PER_ELEMENT);
      const length = Math.min(remaining, this.#availableBytes());
      if (length === 0) break;
      this.#consume(length);
      remaining -= length;
    }
    return requested - remaining;
  }

  async cancel(): Promise<void> {
    if (this.#released) return;
    try {
      await this.#reader.cancel();
    } catch {
      // A failed source read already reports the useful error at the scan boundary.
    } finally {
      this.#reader.releaseLock();
      this.#released = true;
    }
  }

  #availableBytes(): number {
    return this.#bytes.byteLength - this.#byteOffset;
  }

  #clampSize(size: number): number {
    if (!Number.isFinite(size) || size <= 0) return 0;
    return Math.min(Math.floor(size), this.#endOffset - this.#currentOffset);
  }

  #consume(size: number): void {
    this.#byteOffset += size;
    this.#currentOffset += size;
    if (this.#byteOffset === this.#bytes.byteLength) {
      this.#bytes = EMPTY_BYTES;
      this.#byteOffset = 0;
    }
  }

  async #fill(minimum: number): Promise<void> {
    while (this.#availableBytes() < minimum && !this.#done) {
      const result = await this.#reader.read(new Uint8Array(DEFAULT_FILE_READ_WINDOW_BYTES));
      if (result.done) {
        this.#done = true;
        break;
      }
      if (result.value.byteLength === 0) continue;
      this.#append(result.value);
    }
  }

  #append(bytes: Uint8Array): void {
    const available = this.#availableBytes();
    if (available === 0) {
      this.#bytes = bytes;
      this.#byteOffset = 0;
      return;
    }
    const combined = new Uint8Array(available + bytes.byteLength);
    combined.set(this.#bytes.subarray(this.#byteOffset));
    combined.set(bytes, available);
    this.#bytes = combined;
    this.#byteOffset = 0;
  }
}

export const createEbmlStreamReader = (
  file: File,
  startOffset: number,
  endOffset: number
): EbmlStreamReader => {
  const start = Number.isFinite(startOffset)
    ? Math.max(0, Math.min(file.size, Math.floor(startOffset)))
    : 0;
  const end = Number.isFinite(endOffset)
    ? Math.max(start, Math.min(file.size, Math.floor(endOffset)))
    : start;
  return new EbmlStreamReader(file.slice(start, end).stream(), start, end);
};
