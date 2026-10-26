import assert from "node:assert/strict";
import { test } from "node:test";
import type { DecodeResult, Decoder } from "lzma-sdk-decode";
import {
  createLzmaDecompressor, decompressLzmaWithProperties, decompressLzmaWithPropertiesTracked
} from "../../../../analyzers/lzma/decoder.js";
import { lzmaBinary, lzmaData, lzmaProperties } from "../../../fixtures/lzma.js";

const complete = (changes: Partial<DecodeResult> = {}): DecodeResult => ({
  data: new TextEncoder().encode("DATA"), bytesRead: lzmaData.length,
  resultCode: 0, status: 1, ...changes
});
const sdk = (decodeLzma: Decoder["decodeLzma"]): Decoder => ({
  decodeLzma, decodeLzma2: () => { throw new Error("Unexpected LZMA2 call"); }
});

void test("raw decoding preserves binary output and accepts marked streams", async () => {
  assert.deepEqual(await decompressLzmaWithProperties(lzmaProperties, lzmaData, 4n),
    new TextEncoder().encode("DATA"));
  assert.deepEqual(await decompressLzmaWithProperties(lzmaProperties, lzmaBinary, 3n),
    Uint8Array.of(255, 254, 253));
});

void test("tracked decoding returns SDK consumption including the end marker", async () => {
  const result = await decompressLzmaWithPropertiesTracked(
    lzmaProperties, Uint8Array.from([...lzmaData, 42]), 4n);

  assert.deepEqual(result.bytes, new TextEncoder().encode("DATA"));
  assert.equal(result.consumedPackedBytes, 14);
});

void test("untracked decoding rejects trailing input", async () => {
  await assert.rejects(decompressLzmaWithProperties(
    lzmaProperties, Uint8Array.from([...lzmaData, 42]), 4n), /unconsumed input/);
});

void test("the SDK's known-size markerless completion status is accepted", async () => {
  const decode = createLzmaDecompressor(async () => sdk(() => complete({ status: 4 })));

  assert.deepEqual((await decode(lzmaProperties, lzmaData, 4n)).bytes,
    new TextEncoder().encode("DATA"));
});

for (const properties of [[], [93, 0, 0, 1], [93, 0, 0, 1, 0, 0], [93, 0, 0, 1, 256],
  [93, 0, 0, 1, -1], [93, 0, 0, 1, 0.5], [93, 0, 0, 1, NaN]]) {
  void test(`rejects invalid properties ${String(properties)}`, async () => {
    const decode = createLzmaDecompressor(() => { throw new Error("Must not initialize"); });

    await assert.rejects(decode(properties, lzmaData, 4n), /properties/);
  });
}

for (const size of [-1n, 0x1_0000_0000n, BigInt(Number.MAX_SAFE_INTEGER) + 1n]) {
  void test(`rejects unsupported output capacity ${size}`, async () => {
    const decode = createLzmaDecompressor(() => { throw new Error("Must not initialize"); });

    await assert.rejects(decode(lzmaProperties, lzmaData, size), /unpack size/);
  });
}

void test("truncated input and undersized output retain SDK failures", async () => {
  await assert.rejects(decompressLzmaWithProperties(lzmaProperties, lzmaData.subarray(0, 3), 4n),
    /LZMA SDK error/);
  await assert.rejects(decompressLzmaWithProperties(lzmaProperties, lzmaData, 3n), /LZMA SDK error/);
});

void test("decoder initialization is shared by concurrent requests", async () => {
  let calls = 0;
  const decode = createLzmaDecompressor(async () => {
    calls += 1;
    return sdk((input, properties, size) => {
      assert.strictEqual(input, lzmaData);
      assert.deepEqual(properties, Uint8Array.of(93, 0, 0, 1, 0));
      assert.equal(size, 4);
      return complete();
    });
  });

  await Promise.all([decode(lzmaProperties, lzmaData, 4n), decode(lzmaProperties, lzmaData, 4n)]);

  assert.equal(calls, 1);
});

void test("failed initialization can be retried", async () => {
  let calls = 0;
  const decode = createLzmaDecompressor(async () => {
    calls += 1;
    if (calls === 1) throw new Error("WASM unavailable");
    return sdk(() => complete());
  });

  await assert.rejects(decode(lzmaProperties, lzmaData, 4n), /WASM unavailable/);
  assert.deepEqual((await decode(lzmaProperties, lzmaData, 4n)).bytes,
    new TextEncoder().encode("DATA"));
  assert.equal(calls, 2);
});

void test("native traps discard the quarantined decoder before the next file", async () => {
  let calls = 0;
  const decode = createLzmaDecompressor(async () => {
    calls += 1;
    return calls === 1 ? sdk(() => { throw new Error("native trap"); }) : sdk(() => complete());
  });

  await assert.rejects(decode(lzmaProperties, lzmaData, 4n), /native trap/);
  assert.equal((await decode(lzmaProperties, lzmaData, 4n)).consumedPackedBytes, 14);
  assert.equal(calls, 2);
});

for (const status of [0, 2, 3] as const) {
  void test(`rejects incomplete SDK status ${status}`, async () => {
    const decode = createLzmaDecompressor(async () => sdk(() => complete({ status })));

    await assert.rejects(decode(lzmaProperties, lzmaData, 4n), /completion status/);
  });
}

void test("marked output must match the container's declared size", async () => {
  const decode = createLzmaDecompressor(async () => sdk(() => complete({ data: new Uint8Array(3) })));

  await assert.rejects(decode(lzmaProperties, lzmaData, 4n), /output size/);
});

void test("byte-valued properties include both boundaries", async () => {
  const decode = createLzmaDecompressor(async () => sdk((_input, properties) => {
    assert.deepEqual(properties, Uint8Array.of(93, 0, 0, 1, 255));
    return complete();
  }));

  assert.equal((await decode([93, 0, 0, 1, 255], lzmaData, 4n)).bytes.length, 4);
});

void test("zero output capacity is valid", async () => {
  const decode = createLzmaDecompressor(async () => sdk((_input, _properties, size) => {
    assert.equal(size, 0);
    return complete({ data: new Uint8Array(), bytesRead: 0, status: 4 });
  }));

  assert.deepEqual(await decode(lzmaProperties, new Uint8Array(), 0n),
    { bytes: new Uint8Array(), consumedPackedBytes: 0 });
});

void test("wasm32's last output capacity reaches the SDK without an arbitrary cap", async () => {
  const decode = createLzmaDecompressor(async () => sdk((_input, _properties, size) => {
    assert.equal(size, 0xffff_ffff);
    return complete({ resultCode: 2 }); // SZ_ERROR_MEM; do not allocate a real 4 GiB test buffer.
  }));

  await assert.rejects(decode(lzmaProperties, lzmaData, 0xffff_ffffn), /LZMA SDK error 2/);
});

void test("malformed streams preserve the healthy decoder for subsequent files", async () => {
  let loads = 0;
  let calls = 0;
  const decode = createLzmaDecompressor(async () => {
    loads += 1;
    return sdk(() => { calls += 1; return complete({ resultCode: calls === 1 ? 1 : 0 }); });
  });

  await assert.rejects(decode(lzmaProperties, lzmaData, 4n), /LZMA SDK error 1/);
  assert.equal((await decode(lzmaProperties, lzmaData, 4n)).bytes.length, 4);
  assert.equal(loads, 1);
});
