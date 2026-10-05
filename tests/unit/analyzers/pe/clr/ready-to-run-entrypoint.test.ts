import assert from "node:assert/strict";
import test from "node:test";
import { NativeFormatReader } from "../../../../../analyzers/native-aot/native-format-reader.js";
import { decodeReadyToRunEntrypoint } from "../../../../../analyzers/pe/clr/ready-to-run-entrypoint.js";

void test("R2R shared entrypoint decoder handles no-fixup, inline and shared fixup encodings", () => {
  assert.deepEqual(decodeReadyToRunEntrypoint(new NativeFormatReader(Uint8Array.of(12)), 0),
    { runtimeFunctionIndex: 3, fixupOffset: null });
  assert.deepEqual(decodeReadyToRunEntrypoint(new NativeFormatReader(Uint8Array.of(18, 42)), 0),
    { runtimeFunctionIndex: 2, fixupOffset: 1 });
  assert.deepEqual(decodeReadyToRunEntrypoint(new NativeFormatReader(Uint8Array.of(42, 22, 2)), 1),
    { runtimeFunctionIndex: 2, fixupOffset: 1 });
});

void test("R2R shared entrypoint decoder rejects truncated integers and invalid fixup extents", () => {
  assert.throws(() => decodeReadyToRunEntrypoint(new NativeFormatReader(Uint8Array.of(18)), 0), /fixup offset/);
  assert.throws(() => decodeReadyToRunEntrypoint(new NativeFormatReader(Uint8Array.of(22, 100)), 0), /fixup offset/);
  assert.throws(() => decodeReadyToRunEntrypoint(new NativeFormatReader(Uint8Array.of(22)), 0), /outside|bounds/);
});
