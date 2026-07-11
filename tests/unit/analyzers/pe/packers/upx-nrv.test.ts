"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { upxAdler32 } from "../../../../../analyzers/pe/packers/upx-adler32.js";
import { decompressUpxNrv } from "../../../../../analyzers/pe/packers/upx-nrv.js";

const SHORT_OUTPUT_BYTES = 16;
const REAL_PE_OUTPUT_BYTES = 24_955;
const REAL_PE_OUTPUT_ADLER32 = 4_254_996_567;
// These three 8-bit control-stream vectors are the upstream UPX/UCL decompressor
// regression fixtures. Each expands to sixteen 0xff bytes.
// https://github.com/upx/upx/blob/devel/src/compress/compress_ucl.cpp
const SHORT_VECTORS = [
  { method: 3, packed: "kv8QAAAAAABI/w==" },
  { method: 6, packed: "kv8QkkkkkqD/" },
  { method: 9, packed: "kP+wkkkkkqD/" }
] as const;
// These LE32 vectors were produced from the same small PE with UPX 5.1.1 using
// --nrv2b, --nrv2d, and --nrv2e. Adler-32 is the PackHeader u_adler value.
const PE_VECTORS = [
  {
    method: 2,
    packed: "yf83/1WJ5VDHRfwAD7YFAAAQAIPEBF3DABIcQVUB6CRCUFUmVRKCoKhARlVUlI0CFR/yX34S" +
      "AFBFTAEDAIDKUmrgAALZYM32AQsBDgwCQhQQA3Z2s7MAQAsfBgAHLd9kSxdwJwOFhL1l7ygCBwb5" +
      "DxCyDGAMLnRlwr5h3Xh0BxeQswJ9szf75iAuZGF0YfIQB5B/ubAEq0DALnJlbG9jsykbbGBLRCdC" +
      "GwAAAHAEACQAAP8="
  },
  {
    method: 5,
    packed: "yf83/1WJ5VDHRfwAD7YFAAAQAIPEBF3DACodQVUB0SaEoKpNVbKAoKhAQlWoqIUCKz/kv/wS" +
      "AFBFTAEDAIDKUmrgAAIB24Y17wsBDhkCQikQBwEb29p2QBc+BiEPL3a3vMlwTgOFUAQPy0AEtwzz" +
      "YAyg/QAhLnRleHQOF99c7I4hAgb7IC5kYXRhi2A2eSBADwRXwwb5l0DALnJlbG9jYJdESbBtak9C" +
      "NwhQSZIk/w=="
  },
  {
    method: 8,
    packed: "yf8//1WJ5VDHRfwAD7YFAAAQAIPEBF3DACoNQVUB0SYsoKpNVZKAoKhAFlWoqC0CKx/k33wS" +
      "AFBFTAEDAIDKUmrgAAIBb7s97QsBDhgCQikQBwFp2/ayQBc+BiMPLnC295pvTwOFUW8P0lxB8BPzY" +
      "AwI3l8FLnRleHQOFyH3z7VtAgf7IC5kYXRhIZkIvkhADwRXQGi3k7/ALnJlbG9jYJdETyRJuOxC" +
      "NwgAUEmS/w=="
  }
] as const;

const fromBase64 = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, "base64"));

class NrvFixtureWriter {
  readonly #controlBytes: number;
  readonly #bytes: number[] = [];
  #controlOffset = -1;
  #controlBit = 0;

  constructor(controlBits: 8 | 16 | 32) {
    this.#controlBytes = controlBits / 8;
  }

  writeBit(bit: number): void {
    if (this.#controlBit === 0) {
      this.#controlOffset = this.#bytes.length;
      this.#bytes.push(...new Array<number>(this.#controlBytes).fill(0));
      this.#controlBit = this.#controlBytes * 8;
    }
    this.#controlBit -= 1;
    const byteFromMostSignificant = Math.floor(this.#controlBit / 8);
    const bitInByte = this.#controlBit % 8;
    const byteOffset = this.#controlOffset + byteFromMostSignificant;
    this.#bytes[byteOffset] = (this.#bytes[byteOffset] ?? 0) | (bit << bitInByte);
  }

  writeByte(byte: number): void {
    this.#bytes.push(byte);
  }

  result(): Uint8Array {
    return Uint8Array.from(this.#bytes);
  }
}

const write2bPrefix = (writer: NrvFixtureWriter, prefix: number): void => {
  const dataBits = prefix.toString(2).slice(1);
  for (let index = 0; index < dataBits.length; index += 1) {
    writer.writeBit(dataBits[index] === "1" ? 1 : 0);
    writer.writeBit(index === dataBits.length - 1 ? 1 : 0);
  }
};

const createLiteral2bStream = (controlBits: 8 | 16 | 32): Uint8Array => {
  const writer = new NrvFixtureWriter(controlBits);
  writer.writeBit(1);
  writer.writeByte(0xa5);
  writer.writeBit(0);
  write2bPrefix(writer, 0x01000002);
  writer.writeByte(0xff);
  return writer.result();
};

for (const vector of SHORT_VECTORS) {
  void test(`decompressUpxNrv decodes method ${vector.method} 8-bit streams`, () => {
    assert.deepEqual(
      decompressUpxNrv(fromBase64(vector.packed), SHORT_OUTPUT_BYTES, vector.method),
      new Uint8Array(SHORT_OUTPUT_BYTES).fill(0xff)
    );
  });
}

for (const vector of PE_VECTORS) {
  void test(`decompressUpxNrv decodes method ${vector.method} LE32 streams`, () => {
    const unpacked = decompressUpxNrv(
      fromBase64(vector.packed),
      REAL_PE_OUTPUT_BYTES,
      vector.method
    );

    assert.equal(unpacked.byteLength, REAL_PE_OUTPUT_BYTES);
    assert.equal(upxAdler32(unpacked), REAL_PE_OUTPUT_ADLER32);
  });
}

void test("decompressUpxNrv rejects truncated control words", () => {
  assert.throws(() => decompressUpxNrv(Uint8Array.of(0xff), SHORT_OUTPUT_BYTES, 2), /truncated/);
});

void test("decompressUpxNrv rejects output overruns", () => {
  assert.throws(
    () => decompressUpxNrv(fromBase64(SHORT_VECTORS[0].packed), SHORT_OUTPUT_BYTES - 1, 3),
    /output/
  );
});

void test("decompressUpxNrv rejects unconsumed input", () => {
  const packed = fromBase64(SHORT_VECTORS[0].packed);
  const withTail = new Uint8Array(packed.byteLength + 1);
  withTail.set(packed);

  assert.throws(() => decompressUpxNrv(withTail, SHORT_OUTPUT_BYTES, 3), /unconsumed/);
});

void test("decompressUpxNrv rejects unsupported methods", () => {
  assert.throws(() => decompressUpxNrv(new Uint8Array(), 1, 14), /unsupported/);
});

void test("decompressUpxNrv decodes LE16 control streams", () => {
  assert.deepEqual(decompressUpxNrv(createLiteral2bStream(16), 1, 4), Uint8Array.of(0xa5));
});

void test("decompressUpxNrv rejects truncated literal bytes", () => {
  assert.throws(() => decompressUpxNrv(Uint8Array.of(0x80), 1, 3), /input is truncated/);
});

void test("decompressUpxNrv rejects invalid output sizes", () => {
  assert.throws(() => decompressUpxNrv(new Uint8Array(), -1, 3), /output size/);
});

void test("decompressUpxNrv rejects lookbehind before output start", () => {
  const packed = fromBase64(SHORT_VECTORS[0].packed);
  packed[0] = 0;

  assert.throws(() => decompressUpxNrv(packed, SHORT_OUTPUT_BYTES, 3), /lookbehind/);
});

void test("decompressUpxNrv rejects output-size mismatches at the end marker", () => {
  assert.throws(() => decompressUpxNrv(createLiteral2bStream(8), 2, 3), /size does not match/);
});

void test("decompressUpxNrv bounds offset prefix growth", () => {
  const writer = new NrvFixtureWriter(8);
  writer.writeBit(0);
  for (let index = 0; index < 30; index += 1) {
    writer.writeBit(1);
    writer.writeBit(0);
  }

  assert.throws(() => decompressUpxNrv(writer.result(), 1, 3), /offset prefix/);
});
