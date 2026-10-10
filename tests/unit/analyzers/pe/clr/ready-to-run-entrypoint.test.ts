import assert from "node:assert/strict";
import test from "node:test";
import { NativeFormatReader } from "../../../../../analyzers/native-aot/native-format-reader.js";
import { decodeReadyToRunEntrypoint } from "../../../../../analyzers/pe/clr/ready-to-run-entrypoint.js";

void test("R2R shared entrypoint decoder handles no-fixup, inline and shared fixup encodings", () => {
  // NativeFormat stores this entry as (runtime index << 1) with no fixup flag.
  assert.deepEqual(decodeReadyToRunEntrypoint(new NativeFormatReader(Uint8Array.of(12)), 0),
    { runtimeFunctionIndex: 3, fixupOffset: null });
  // Entry 9 means index 2 plus inline-fixup flag; the next compressed integer is its payload.
  assert.deepEqual(decodeReadyToRunEntrypoint(new NativeFormatReader(Uint8Array.of(18, 42)), 0),
    { runtimeFunctionIndex: 2, fixupOffset: 1 });
  // At offset 1, entry 11 means index 2 plus shared-fixup flags; value 1 looks back from offset 2.
  assert.deepEqual(decodeReadyToRunEntrypoint(new NativeFormatReader(Uint8Array.of(42, 22, 2)), 1),
    { runtimeFunctionIndex: 2, fixupOffset: 1 });
});

void test("R2R shared entrypoint decoder rejects truncated integers and invalid fixup extents", () => {
  // A flagged entry has no following payload byte, then a shared entry's distance exceeds its offset.
  assert.throws(() => decodeReadyToRunEntrypoint(new NativeFormatReader(Uint8Array.of(18)), 0), /fixup offset/);
  assert.throws(() => decodeReadyToRunEntrypoint(new NativeFormatReader(Uint8Array.of(22, 100)), 0), /fixup offset/);
  assert.throws(() => decodeReadyToRunEntrypoint(new NativeFormatReader(Uint8Array.of(22)), 0), /outside|bounds/);
});
