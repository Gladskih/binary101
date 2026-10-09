import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { zstdCompressSync, constants } from "node:zlib";
import { decompressDwarfZstd } from "../../../../analyzers/dwarf/zstd.js";

const observeDecoderMemory = () => {
  const instantiate = WebAssembly.instantiate.bind(WebAssembly);
  const allocations = new Set<number>();
  let remaining = Number.POSITIVE_INFINITY;
  const initialization = mock.method(WebAssembly, "instantiate",
    async (buffer: BufferSource, imports?: WebAssembly.Imports) => {
      const result = await instantiate(buffer, imports);
      const allocate = result.instance.exports["malloc"] as (size: number) => number;
      const release = result.instance.exports["free"] as (pointer: number) => void;
      return { ...result, instance: { exports: { ...result.instance.exports,
        malloc: (size: number) => {
          if (remaining-- === 0) return 0;
          const pointer = allocate(size);
          allocations.add(pointer);
          return pointer;
        },
        free: (pointer: number) => {
          assert.ok(allocations.delete(pointer), "decoder released memory twice");
          release(pointer);
        }
      } } as unknown as WebAssembly.Instance };
    });
  return { initialization, allocations, failAfter: (count: number) => { remaining = count; } };
};

void test("Zstandard decodes actual compressed frames and reuses initialization", async () => {
  const contents = new TextEncoder().encode("DWARF debug data ".repeat(100));
  const memory = observeDecoderMemory();
  try {
    assert.deepEqual(await decompressDwarfZstd(zstdCompressSync(contents), contents.length), contents);
    assert.deepEqual(await decompressDwarfZstd(zstdCompressSync(contents), contents.length), contents);
    assert.equal(memory.initialization.mock.callCount(), 1);
    memory.failAfter(0);
    await assert.rejects(decompressDwarfZstd(zstdCompressSync(contents), contents.length), /allocate memory/);
    assert.equal(memory.allocations.size, 0);
    memory.failAfter(1);
    await assert.rejects(decompressDwarfZstd(zstdCompressSync(contents), contents.length), /allocate memory/);
    assert.equal(memory.allocations.size, 0);
    memory.failAfter(0);
    await assert.rejects(decompressDwarfZstd(zstdCompressSync(contents), contents.length), /allocate memory/);
    memory.failAfter(Number.POSITIVE_INFINITY);
    assert.deepEqual(await decompressDwarfZstd(zstdCompressSync(contents), contents.length), contents);
    assert.equal(memory.allocations.size, 0);
  } finally {
    memory.initialization.mock.restore();
  }
});

void test("Zstandard validates empty output and default decode size", async () => {
  assert.deepEqual(await decompressDwarfZstd(zstdCompressSync(new Uint8Array()), 0), new Uint8Array());
  await assert.rejects(decompressDwarfZstd(zstdCompressSync(new Uint8Array([1])), 0), /does not match/);
});

void test("Zstandard rejects a missing frame even when zero output is declared", async () => {
  await assert.rejects(decompressDwarfZstd(new Uint8Array(), 0), /Zstandard payload is empty/);
});

void test("Zstandard rejects size mismatches and corruption, then remains usable", async () => {
  const contents = new TextEncoder().encode("DWARF");
  const compressed = zstdCompressSync(contents);
  await assert.rejects(decompressDwarfZstd(compressed, contents.length + 1), /does not match declared size/);
  await assert.rejects(decompressDwarfZstd(compressed, contents.length - 1), /decoder error/);
  await assert.rejects(decompressDwarfZstd(compressed.subarray(0, compressed.length - 1), contents.length),
    /decoder error/);
  await assert.rejects(decompressDwarfZstd(new Uint8Array([0]), 0), /decoder error/);
  assert.deepEqual(await decompressDwarfZstd(compressed, contents.length), contents);
});

void test("Zstandard checks frame checksums instead of accepting a decoded prefix", async () => {
  const contents = new TextEncoder().encode("DWARF");
  const compressed = zstdCompressSync(contents, { params: { [constants.ZSTD_c_checksumFlag]: 1 } });
  compressed[compressed.length - 1]! ^= 1;
  await assert.rejects(decompressDwarfZstd(compressed, contents.length), /decoder error/);
});

for (const size of [-1, Number.NaN, 0.5, 2 ** 32, Number.MAX_SAFE_INTEGER + 1]) {
  void test(`Zstandard rejects unrepresentable output size ${size}`, async () => {
    await assert.rejects(decompressDwarfZstd(new Uint8Array(), size), /wasm32 address space/);
  });
}

void test("Zstandard rejects input lengths outside its native address space before allocating", async () => {
  // Model the wasm32 boundary without allocating a four-gigabyte test buffer.
  const input = Object.defineProperty(new Uint8Array(), "length", { value: 2 ** 32 });
  await assert.rejects(decompressDwarfZstd(input, 0), /wasm32 address space/);
});
