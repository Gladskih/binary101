"use strict";

type NrvMethod = 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10;
type NrvOffset = { distance: number; end: boolean; lengthBit: number };

// UPX compression method values and NRV bit-buffer widths are stable ABI values.
// https://github.com/upx/upx/blob/devel/src/conf.h
const isNrvMethod = (method: number): method is NrvMethod => method >= 2 && method <= 10;
const MAX_OFFSET_PREFIX = 0x01000002;

class NrvBitReader {
  readonly #bytes: Uint8Array;
  readonly #controlBits: 8 | 16 | 32;
  #position = 0;
  #control = 0;
  #remaining = 0;

  constructor(bytes: Uint8Array, controlBits: 8 | 16 | 32) {
    this.#bytes = bytes;
    this.#controlBits = controlBits;
  }

  get position(): number {
    return this.#position;
  }

  readByte(): number {
    if (this.#position >= this.#bytes.byteLength) throw new Error("UPX NRV input is truncated.");
    return this.#bytes[this.#position++] ?? 0;
  }

  readBit(): number {
    if (this.#remaining === 0) this.#refill();
    const bit = this.#controlBits === 32
      ? this.#control >>> 31
      : this.#control >>> (this.#controlBits - 1);
    this.#control = (this.#control << 1) >>> 0;
    this.#remaining -= 1;
    return bit & 1;
  }

  #refill(): void {
    if (this.#position > this.#bytes.byteLength - this.#controlBits / 8) {
      throw new Error("UPX NRV control word is truncated.");
    }
    if (this.#controlBits === 8) this.#control = this.readByte();
    if (this.#controlBits === 16) {
      this.#control = this.readByte() | (this.readByte() << 8);
    }
    if (this.#controlBits === 32) {
      this.#control = (
        this.readByte() |
        (this.readByte() << 8) |
        (this.readByte() << 16) |
        (this.readByte() << 24)
      ) >>> 0;
    }
    this.#remaining = this.#controlBits;
  }
}

const controlBitsForMethod = (method: NrvMethod): 8 | 16 | 32 =>
  method % 3 === 2 ? 32 : method % 3 === 0 ? 8 : 16;

const appendBit = (value: number, reader: NrvBitReader): number => {
  const next = value * 2 + reader.readBit();
  if (next > MAX_OFFSET_PREFIX) throw new Error("UPX NRV offset prefix is invalid.");
  return next;
};

const read2bPrefix = (reader: NrvBitReader): number => {
  let prefix = 1;
  do prefix = appendBit(prefix, reader);
  while (reader.readBit() === 0);
  return prefix;
};

const read2dePrefix = (reader: NrvBitReader): number => {
  let prefix = 1;
  for (;;) {
    prefix = appendBit(prefix, reader);
    if (reader.readBit() === 1) return prefix;
    prefix = appendBit(prefix - 1, reader);
  }
};

const read2bOffset = (reader: NrvBitReader, previous: number): NrvOffset => {
  const prefix = read2bPrefix(reader);
  if (prefix === 2) return { distance: previous, end: false, lengthBit: 0 };
  const encoded = (prefix - 3) * 256 + reader.readByte();
  return {
    distance: encoded + 1,
    end: encoded === 0xffffffff,
    lengthBit: 0
  };
};

const read2deOffset = (reader: NrvBitReader, previous: number): NrvOffset => {
  const prefix = read2dePrefix(reader);
  if (prefix === 2) return { distance: previous, end: false, lengthBit: -1 };
  const encoded = (prefix - 3) * 256 + reader.readByte();
  return {
    distance: Math.floor(encoded / 2) + 1,
    end: encoded === 0xffffffff,
    lengthBit: (~encoded) & 1
  };
};

const readExtendedLength = (reader: NrvBitReader, initial: number, extra: number): number => {
  let length = initial;
  do length = length * 2 + reader.readBit();
  while (reader.readBit() === 0);
  return length + extra;
};

const read2bLength = (reader: NrvBitReader, distance: number): number => {
  let length = reader.readBit() * 2 + reader.readBit();
  length = length === 0 ? readExtendedLength(reader, 1, 3) : length + 1;
  return length + (distance > 0x0d00 ? 1 : 0);
};

const read2dLength = (reader: NrvBitReader, distance: number, firstBit: number): number => {
  let length = (firstBit < 0 ? reader.readBit() : firstBit) * 2 + reader.readBit();
  length = length === 0 ? readExtendedLength(reader, 1, 3) : length + 1;
  return length + (distance > 0x0500 ? 1 : 0);
};

const read2eLength = (reader: NrvBitReader, distance: number, offsetBit: number): number => {
  let length = offsetBit < 0 ? reader.readBit() : offsetBit;
  if (length === 1) length = 1 + reader.readBit();
  else if (reader.readBit() === 1) length = 3 + reader.readBit();
  else length = readExtendedLength(reader, 1, 3);
  return length + 1 + (distance > 0x0500 ? 1 : 0);
};

const copyMatch = (output: Uint8Array, position: number, distance: number, length: number): number => {
  if (distance < 1 || distance > position) {
    throw new Error(`UPX NRV lookbehind is out of bounds (${distance} at ${position}).`);
  }
  if (length < 1 || length > output.byteLength - position) throw new Error("UPX NRV output overrun.");
  for (let index = 0; index < length; index += 1) {
    output[position + index] = output[position + index - distance] ?? 0;
  }
  return position + length;
};

const readLength = (
  reader: NrvBitReader,
  method: NrvMethod,
  distance: number,
  lengthBit: number
): number => {
  if (method <= 4) return read2bLength(reader, distance);
  if (method <= 7) return read2dLength(reader, distance, lengthBit);
  return read2eLength(reader, distance, lengthBit);
};

export const decompressUpxNrv = (
  packed: Uint8Array,
  unpackedSize: number,
  method: number
): Uint8Array => {
  if (!isNrvMethod(method)) throw new Error(`UPX NRV method ${method} is unsupported.`);
  if (!Number.isSafeInteger(unpackedSize) || unpackedSize < 0) {
    throw new Error("UPX NRV output size is invalid.");
  }
  const reader = new NrvBitReader(packed, controlBitsForMethod(method));
  const output = new Uint8Array(unpackedSize);
  let outputPosition = 0;
  let previousOffset = 1;
  for (;;) {
    while (reader.readBit() === 1) {
      if (outputPosition >= output.byteLength) throw new Error("UPX NRV output overrun.");
      output[outputPosition++] = reader.readByte();
    }
    const offset = method <= 4
      ? read2bOffset(reader, previousOffset)
      : read2deOffset(reader, previousOffset);
    if (offset.end) {
      if (reader.position !== packed.byteLength) throw new Error("UPX NRV input is unconsumed.");
      if (outputPosition !== output.byteLength) throw new Error("UPX NRV output size does not match.");
      return output;
    }
    if (offset.distance !== previousOffset || offset.lengthBit >= 0) previousOffset = offset.distance;
    outputPosition = copyMatch(
      output,
      outputPosition,
      offset.distance,
      readLength(reader, method, offset.distance, offset.lengthBit)
    );
  }
};
