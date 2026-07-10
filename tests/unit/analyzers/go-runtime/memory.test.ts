"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readExact, readWord, toView } from "../../../../analyzers/go-runtime/memory.js";
import type { GoRuntimeAddressSpace } from "../../../../analyzers/go-runtime/types.js";

const image = (bytes: Uint8Array): GoRuntimeAddressSpace => ({
  pointerSize: 4,
  isMappedRange: (address, size) => address === 0x1000n && size <= bytes.length,
  isExecutableRange: () => false,
  readMapped: async (_address, size) => bytes.slice(0, size)
});

void test("readWord reads 32-bit and 64-bit little-endian words", () => {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0, 0x1122_3344_5566_7788n, true);

  assert.equal(readWord(view, 0, 4), 0x5566_7788n);
  assert.equal(readWord(view, 0, 8), 0x1122_3344_5566_7788n);
  assert.equal(toView(bytes).byteLength, 8);
});

void test("readExact rejects invalid, unmapped, and short reads", async () => {
  const bytes = new Uint8Array([1, 2, 3, 4]);
  const shortImage = image(bytes);
  shortImage.readMapped = async () => bytes.slice(0, 2);

  assert.equal(await readExact(image(bytes), 0x1000n, -1), null);
  assert.equal(await readExact(image(bytes), 0x2000n, 2), null);
  assert.equal(await readExact(shortImage, 0x1000n, 4), null);
  assert.deepEqual(await readExact(image(bytes), 0x1000n, 4), bytes);
});
