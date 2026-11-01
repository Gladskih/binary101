"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { DWARF_ENCODING } from "./constants.js";
import type { DwarfSectionInput } from "./types.js";

// A small view into the shared reader's window removes per-field async/cache work.
// Profiling attributes about 0.3 s to cursor/reader byte operations.
const CURSOR_WINDOW_BYTES = 4 * 1024;

export class DwarfCursor {
  position: number;
  readonly end: number;
  readonly #reader: FileRangeReader;
  readonly #section: DwarfSectionInput;
  readonly #littleEndian: boolean;
  readonly #issues: string[];
  #failed = false;
  #window: DataView = new DataView(new ArrayBuffer(0));
  #windowBytes: Uint8Array = new Uint8Array(0);
  #windowStart = 0;

  constructor(
    reader: FileRangeReader,
    section: DwarfSectionInput,
    position: number,
    end: number,
    littleEndian: boolean,
    issues: string[]
  ) {
    this.#reader = reader;
    this.#section = section;
    this.position = position;
    this.end = Math.min(end, section.size);
    this.#littleEndian = littleEndian;
    this.#issues = issues;
    if (![section.offset, section.size, position, end].every(Number.isSafeInteger) ||
        section.offset < 0 || section.size < 0 || position < 0 || end < position ||
        position > section.size || section.offset > reader.size) {
      this.fail("Invalid DWARF cursor range");
    }
  }

  get failed(): boolean {
    return this.#failed;
  }

  uint8(): Promise<number | null> {
    return this.#number(Uint8Array.BYTES_PER_ELEMENT, (view, offset) => view.getUint8(offset));
  }

  uint16(): Promise<number | null> {
    return this.#number(Uint16Array.BYTES_PER_ELEMENT, (view, offset) =>
      view.getUint16(offset, this.#littleEndian));
  }

  uint32(): Promise<number | null> {
    return this.#number(Uint32Array.BYTES_PER_ELEMENT, (view, offset) =>
      view.getUint32(offset, this.#littleEndian));
  }

  uint64(): Promise<bigint | null> {
    return this.#number(BigUint64Array.BYTES_PER_ELEMENT, (view, offset) =>
      view.getBigUint64(offset, this.#littleEndian));
  }

  async unsigned(byteLength: number): Promise<bigint | null> {
    if (byteLength === Uint8Array.BYTES_PER_ELEMENT) return this.#toBigInt(await this.uint8());
    if (byteLength === Uint16Array.BYTES_PER_ELEMENT) return this.#toBigInt(await this.uint16());
    if (byteLength === Uint32Array.BYTES_PER_ELEMENT) return this.#toBigInt(await this.uint32());
    if (byteLength === BigUint64Array.BYTES_PER_ELEMENT) return this.uint64();
    return this.#arbitraryUnsigned(byteLength);
  }

  async #arbitraryUnsigned(byteLength: number): Promise<bigint | null> {
    // DWARF 5 Table 7.5 also defines three-byte strx3/addrx3 operands.
    if (!Number.isSafeInteger(byteLength) || byteLength <= 0) {
      this.fail(`Invalid ${byteLength}-byte integer`);
      return null;
    }
    const view = await this.#view(byteLength);
    if (!view) return null;
    let value = 0n;
    for (let index = 0; index < byteLength; index += 1) {
      const offset = this.#littleEndian ? byteLength - 1 - index : index;
      value = (value << BigInt(DWARF_ENCODING.bitsPerByte)) | BigInt(view.getUint8(offset));
    }
    return value;
  }

  // DWARF 5, 7.6: LEB128 ends at a byte without the continuation bit.
  // https://dwarfstd.org/doc/DWARF5.pdf
  async uleb(): Promise<bigint | null> {
    let value = 0n;
    for (let index = 0; ; index += 1) {
      const ready = this.#prepare(1);
      if (!(typeof ready === "boolean" ? ready : await ready)) return null;
      const byte = this.#window.getUint8(this.position++ - this.#windowStart);
      value |= BigInt(byte & DWARF_ENCODING.lebPayloadMask) <<
        BigInt(index * DWARF_ENCODING.lebPayloadBits);
      if ((byte & DWARF_ENCODING.lebContinuationBit) === 0) return value;
    }
  }

  async sleb(): Promise<bigint | null> {
    let value = 0n;
    for (let index = 0; ; index += 1) {
      const ready = this.#prepare(1);
      if (!(typeof ready === "boolean" ? ready : await ready)) return null;
      const byte = this.#window.getUint8(this.position++ - this.#windowStart);
      const shift = BigInt(index * DWARF_ENCODING.lebPayloadBits);
      value |= BigInt(byte & DWARF_ENCODING.lebPayloadMask) << shift;
      if ((byte & DWARF_ENCODING.lebContinuationBit) === 0) {
        return (byte & DWARF_ENCODING.lebSignBit) !== 0
          ? value | (-1n << (shift + BigInt(DWARF_ENCODING.lebPayloadBits)))
          : value;
      }
    }
  }

  async cstring(): Promise<string | null> {
    const decoder = new TextDecoder();
    let captured = "";
    while (this.position < this.end) {
      const ready = this.#prepare(1);
      if (!(typeof ready === "boolean" ? ready : await ready)) return null;
      const start = this.position - this.#windowStart;
      const terminator = this.#windowBytes.indexOf(DWARF_ENCODING.nullByte, start);
      const end = terminator < 0 ? this.#windowBytes.length : terminator;
      this.position = this.#windowStart + end;
      captured += decoder.decode(this.#windowBytes.subarray(start, end), { stream: true });
      if (terminator < 0) continue;
      this.position += 1;
      return captured + decoder.decode();
    }
    this.fail("Unterminated DWARF string");
    return null;
  }

  async bytes(byteLength: bigint | number): Promise<Uint8Array | null> {
    const length = Number(byteLength);
    if (!Number.isSafeInteger(length) || length < 0) {
      this.fail(`Invalid block length ${byteLength.toString()}`);
      return null;
    }
    const view = await this.#view(length);
    return view ? new Uint8Array(view.buffer, view.byteOffset, view.byteLength).slice() : null;
  }

  skip(byteLength: bigint | number): boolean {
    const length = typeof byteLength === "bigint" ? Number(byteLength) : byteLength;
    if (!Number.isSafeInteger(length) || length < 0 || length > this.end - this.position) {
      this.fail(`Cannot skip ${byteLength.toString()} bytes`);
      return false;
    }
    this.position += length;
    return true;
  }

  fail(message: string): void {
    if (this.#failed) return;
    this.#failed = true;
    this.#issues.push(
      `${this.#section.name} at 0x${this.position.toString(16)}: ${message}.`
    );
    this.position = this.end;
  }

  notice(message: string): void {
    this.#issues.push(
      `${this.#section.name} at 0x${this.position.toString(16)}: ${message}.`
    );
  }

  #toBigInt(value: number | null): bigint | null {
    return value == null ? null : BigInt(value);
  }

  async #number<Value>(
    byteLength: number,
    read: (view: DataView, offset: number) => Value
  ): Promise<Value | null> {
    const ready = this.#prepare(byteLength);
    if (!(typeof ready === "boolean" ? ready : await ready)) return null;
    const offset = this.position - this.#windowStart;
    this.position += byteLength;
    return read(this.#window, offset);
  }

  async #view(byteLength: number): Promise<DataView | null> {
    return this.#number(byteLength, (view, offset) =>
      new DataView(view.buffer, view.byteOffset + offset, byteLength));
  }

  #prepare(byteLength: number): boolean | Promise<boolean> {
    if (this.#failed) return false;
    if (!Number.isSafeInteger(this.position) || this.position < 0) {
      this.fail("Invalid DWARF cursor position");
      return false;
    }
    if (byteLength > this.end - this.position) {
      this.fail(`Truncated value needs ${byteLength} bytes`);
      return false;
    }
    const offset = this.position - this.#windowStart;
    if (offset >= 0 && byteLength <= this.#window.byteLength - offset) return true;
    return this.#refill(byteLength);
  }

  async #refill(byteLength: number): Promise<boolean> {
    // Align random string/unit starts so local windows can share the reader cache.
    const start = Math.floor(this.position / CURSOR_WINDOW_BYTES) * CURSOR_WINDOW_BYTES;
    const required = this.position - start + byteLength;
    const view = await this.#reader.read(this.#section.offset + start,
      Math.min(this.end - start, Math.max(CURSOR_WINDOW_BYTES, required)));
    if (view.byteLength < required) {
      this.fail(`File ended while reading ${byteLength} bytes`);
      return false;
    }
    this.#windowStart = start;
    this.#window = view;
    this.#windowBytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    return true;
  }
}
