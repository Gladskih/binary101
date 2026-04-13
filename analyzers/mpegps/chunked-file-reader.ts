"use strict";

export class ChunkedFileReader {
  readonly file: File;
  readonly chunkSize: number;
  readonly overlap: number;

  chunkBase = -1;
  chunkBytes = new Uint8Array(0);

  constructor(file: File, chunkSize: number, overlap: number) {
    this.file = file;
    this.chunkSize = chunkSize;
    this.overlap = overlap;
  }

  hasBytes(offset: number, requiredBytes: number): boolean {
    if (offset < 0 || requiredBytes < 0) return false;
    if (offset + requiredBytes > this.file.size) return false;
    if (this.chunkBase < 0) return false;
    const local = offset - this.chunkBase;
    return local >= 0 && local + requiredBytes <= this.chunkBytes.length;
  }

  private async loadChunk(offset: number, requiredBytes: number): Promise<void> {
    const base = Math.floor(offset / this.chunkSize) * this.chunkSize;
    const localRequired = (offset - base) + requiredBytes;
    const targetSize = Math.max(this.chunkSize + this.overlap, localRequired);
    const end = Math.min(this.file.size, base + targetSize);
    this.chunkBytes = new Uint8Array(await this.file.slice(base, end).arrayBuffer());
    this.chunkBase = base;
  }

  async ensureBytes(offset: number, requiredBytes: number): Promise<boolean> {
    if (offset < 0 || requiredBytes < 0) return false;
    if (offset + requiredBytes > this.file.size) return false;
    if (this.hasBytes(offset, requiredBytes)) return true;
    await this.loadChunk(offset, requiredBytes);
    return this.hasBytes(offset, requiredBytes);
  }
}
