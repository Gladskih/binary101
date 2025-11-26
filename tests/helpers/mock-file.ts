"use strict";

export class MockFile extends Blob implements File {
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
}

export const toUint8Array = (
  value: Uint8Array | ArrayBuffer | ArrayLike<number>
): Uint8Array => {
  if (value instanceof Uint8Array) return value;
  return new Uint8Array(value);
};
