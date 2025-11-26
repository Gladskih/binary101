"use strict";

export class MockFile {
  readonly bytes: Uint8Array;
  readonly name: string;
  readonly type: string;
  readonly size: number;

  constructor(bytes: Uint8Array, name = "mock.bin", type = "application/octet-stream") {
    this.bytes = bytes;
    this.name = name;
    this.type = type;
    this.size = bytes.length;
  }

  slice(start = 0, end?: number | null): MockFile {
    const clampedStart = Math.max(0, start);
    const clampedEnd = end == null ? this.size : Math.min(end, this.size);
    const sliced = this.bytes.slice(clampedStart, clampedEnd);
    return new MockFile(sliced, this.name, this.type);
  }

  async arrayBuffer(): Promise<ArrayBuffer> {
    return this.bytes.slice().buffer;
  }
}

export const toUint8Array = (
  value: Uint8Array | ArrayBuffer | ArrayLike<number>
): Uint8Array => {
  if (value instanceof Uint8Array) return value;
  return new Uint8Array(value);
};
