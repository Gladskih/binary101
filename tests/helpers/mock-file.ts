"use strict";

import {
  createFileRangeReader,
  type DirectFileRangeReader,
  type FileRangeReader
} from "../../analyzers/file-range-reader.js";

export class MockFile extends Blob implements File, FileRangeReader {
  #reader: DirectFileRangeReader | null = null;
  readonly data: Uint8Array;
  readonly name: string;
  readonly lastModified: number;
  readonly webkitRelativePath: string;

  constructor(bytes: Uint8Array, name = "mock.bin", type = "application/octet-stream") {
    const copy = new Uint8Array(bytes);
    super([copy.buffer], { type });
    this.data = copy;
    this.name = name;
    this.lastModified = Date.now();
    this.webkitRelativePath = "";
  }

  get [Symbol.toStringTag](): string {
    return "File";
  }

  read(offset: number, size: number): Promise<DataView> {
    this.#reader ??= createFileRangeReader(this, 0, this.size, 0);
    return this.#reader.read(offset, size);
  }

  readBytes(offset: number, size: number): Promise<Uint8Array> {
    this.#reader ??= createFileRangeReader(this, 0, this.size, 0);
    return this.#reader.readBytes(offset, size);
  }

  readInto(
    offset: number,
    destination: Uint8Array<ArrayBuffer>
  ): Promise<Uint8Array<ArrayBuffer>> {
    this.#reader ??= createFileRangeReader(this, 0, this.size, 0);
    return this.#reader.readInto(offset, destination);
  }
}

export const toUint8Array = (
  value: Uint8Array | ArrayBuffer | ArrayLike<number>
): Uint8Array => {
  if (value instanceof Uint8Array) return value;
  return new Uint8Array(value);
};
