import assert from "node:assert/strict";
import { test } from "node:test";
import { deflateSync } from "node:zlib";
import { decompressSectionZlib } from "../../../analyzers/section-zlib.js";

void test("zlib section output matches its declared size including empty output", async () => {
  assert.deepEqual(await decompressSectionZlib(deflateSync(Uint8Array.from([1, 2, 3])), 3), Uint8Array.from([1, 2, 3]));
  assert.deepEqual(await decompressSectionZlib(deflateSync(new Uint8Array()), 0), new Uint8Array());
});
void test("zlib rejects shorter, longer and corrupt output", async () => {
  const compressed = deflateSync(Uint8Array.from([1, 2, 3]));
  await assert.rejects(decompressSectionZlib(compressed, 2), /exceeds declared/);
  await assert.rejects(decompressSectionZlib(compressed, 4), /does not match/);
  await assert.rejects(decompressSectionZlib(Uint8Array.from([1, 2, 3]), 3));
});
void test("missing browser decompressor produces a useful error", async context => {
  context.mock.property(globalThis, "DecompressionStream", undefined);
  await assert.rejects(decompressSectionZlib(new Uint8Array(), 0), /browser does not provide/);
});
