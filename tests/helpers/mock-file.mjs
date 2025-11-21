"use strict";

export class MockFile {
  constructor(bytes, name = "mock.bin", type = "application/octet-stream") {
    this.bytes = bytes;
    this.name = name;
    this.type = type;
    this.size = bytes.length;
  }

  slice(start = 0, end = this.size) {
    const clampedStart = Math.max(0, start);
    const clampedEnd = end == null ? this.size : Math.min(end, this.size);
    const sliced = this.bytes.slice(clampedStart, clampedEnd);
    return new MockFile(sliced, this.name, this.type);
  }

  async arrayBuffer() {
    return this.bytes.buffer.slice(
      this.bytes.byteOffset,
      this.bytes.byteOffset + this.bytes.byteLength
    );
  }
}

export const toUint8Array = value => {
  if (value instanceof Uint8Array) return value;
  return new Uint8Array(value);
};
