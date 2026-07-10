"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { DWARF_ENCODING, DWARF_LIMIT } from "./constants.js";
import type { DwarfSectionInput } from "./types.js";

export class DwarfCursor {
  position: number;
  readonly end: number;
  readonly #reader: FileRangeReader;
  readonly #section: DwarfSectionInput;
  readonly #littleEndian: boolean;
  readonly #issues: string[];
  #failed = false;

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
  }

  get failed(): boolean {
    return this.#failed;
  }

  async uint8(): Promise<number | null> {
    return this.#number(Uint8Array.BYTES_PER_ELEMENT, view => view.getUint8(0));
  }

  async uint16(): Promise<number | null> {
    return this.#number(Uint16Array.BYTES_PER_ELEMENT, view =>
      view.getUint16(0, this.#littleEndian));
  }

  async uint32(): Promise<number | null> {
    return this.#number(Uint32Array.BYTES_PER_ELEMENT, view =>
      view.getUint32(0, this.#littleEndian));
  }

  async uint64(): Promise<bigint | null> {
    const view = await this.#view(BigUint64Array.BYTES_PER_ELEMENT);
    return view ? view.getBigUint64(0, this.#littleEndian) : null;
  }

  async unsigned(byteLength: number): Promise<bigint | null> {
    if (byteLength === Uint8Array.BYTES_PER_ELEMENT) return this.#toBigInt(await this.uint8());
    if (byteLength === Uint16Array.BYTES_PER_ELEMENT) return this.#toBigInt(await this.uint16());
    if (byteLength === Uint32Array.BYTES_PER_ELEMENT) return this.#toBigInt(await this.uint32());
    if (byteLength === BigUint64Array.BYTES_PER_ELEMENT) return this.uint64();
    this.fail(`Unsupported ${byteLength}-byte integer`);
    return null;
  }

  async uleb(): Promise<bigint | null> {
    let value = 0n;
    for (let index = 0; index < DWARF_LIMIT.maximumLebBytes; index += 1) {
      const byte = await this.uint8();
      if (byte == null) return null;
      value |= BigInt(byte & DWARF_ENCODING.lebPayloadMask) <<
        BigInt(index * DWARF_ENCODING.lebPayloadBits);
      if ((byte & DWARF_ENCODING.lebContinuationBit) === 0) return value;
    }
    this.fail(`ULEB128 value exceeds ${DWARF_LIMIT.maximumLebBytes} bytes`);
    return null;
  }

  async sleb(): Promise<bigint | null> {
    let value = 0n;
    for (let index = 0; index < DWARF_LIMIT.maximumLebBytes; index += 1) {
      const byte = await this.uint8();
      if (byte == null) return null;
      const shift = BigInt(index * DWARF_ENCODING.lebPayloadBits);
      value |= BigInt(byte & DWARF_ENCODING.lebPayloadMask) << shift;
      if ((byte & DWARF_ENCODING.lebContinuationBit) === 0) {
        return (byte & DWARF_ENCODING.lebSignBit) !== 0
          ? value | (-1n << (shift + BigInt(DWARF_ENCODING.lebPayloadBits)))
          : value;
      }
    }
    this.fail(`SLEB128 value exceeds ${DWARF_LIMIT.maximumLebBytes} bytes`);
    return null;
  }

  async cstring(): Promise<string | null> {
    const captured: number[] = [];
    let truncated = false;
    while (this.position < this.end) {
      const byte = await this.uint8();
      if (byte == null) return null;
      if (byte === DWARF_ENCODING.nullByte) {
        if (truncated) {
          this.notice(
            `String value was truncated to ${DWARF_LIMIT.maximumCapturedStringBytes} ` +
            `decoded bytes`
          );
        }
        return new TextDecoder().decode(Uint8Array.from(captured));
      }
      if (captured.length < DWARF_LIMIT.maximumCapturedStringBytes) {
        captured.push(byte);
      } else {
        truncated = true;
      }
    }
    this.fail("Unterminated DWARF string");
    return null;
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

  async #number(
    byteLength: number,
    read: (view: DataView) => number
  ): Promise<number | null> {
    const view = await this.#view(byteLength);
    return view ? read(view) : null;
  }

  async #view(byteLength: number): Promise<DataView | null> {
    if (byteLength > this.end - this.position) {
      this.fail(`Truncated value needs ${byteLength} bytes`);
      return null;
    }
    const view = await this.#reader.read(this.#section.offset + this.position, byteLength);
    if (view.byteLength !== byteLength) {
      this.fail(`File ended while reading ${byteLength} bytes`);
      return null;
    }
    this.position += byteLength;
    return view;
  }
}
