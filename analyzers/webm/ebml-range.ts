import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import { MAX_ELEMENT_HEADER } from "./constants.js";
import { readElementHeader, type EbmlElementHeader } from "./ebml.js";
import type { Issues } from "./types.js";

// Block analysis reads headers and short prefixes. Reuse nearby reads while skipping payloads.
export const EBML_SCAN_WINDOW_BYTES = 1024 * 1024;

export class EbmlRangeReader {
  private position = 0;
  private readonly range: FileRangeReader;
  constructor(file: File, private readonly start: number, end: number,
    private readonly signal?: AbortSignal) {
    this.range = createFileRangeReader(file, start, end - start, EBML_SCAN_WINDOW_BYTES);
  }
  get offset(): number {
    return this.start + this.position;
  }
  async readElementHeader(end: number, issues: Issues): Promise<EbmlElementHeader | null> {
    this.signal?.throwIfAborted();
    const available = this.availableBytes(Math.min(MAX_ELEMENT_HEADER, end - this.offset));
    if (available === 0) return null;
    const view = await this.range.read(this.position, available);
    if (!view.byteLength) {
      issues.push(`Unexpected end of file at ${this.offset}.`);
      return null;
    }
    const header = readElementHeader(view, 0, this.offset, issues);
    if (header) this.position += header.headerSize;
    return header;
  }
  async readBytes(size: number): Promise<Uint8Array> {
    this.signal?.throwIfAborted();
    const bytes = await this.range.readBytes(this.position, this.availableBytes(size));
    this.position += bytes.byteLength;
    return bytes;
  }
  skip(size: number): Promise<number> {
    this.signal?.throwIfAborted();
    const skipped = this.availableBytes(size);
    this.position += skipped;
    return Promise.resolve(skipped);
  }
  private availableBytes(size: number): number {
    if (!Number.isFinite(size)) return 0;
    return Math.max(0, Math.min(Math.floor(size), this.range.size - this.position));
  }
}
