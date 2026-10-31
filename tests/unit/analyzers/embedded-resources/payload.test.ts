import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveResourcePayload } from "../../../../analyzers/embedded-resources/payload.js";

void test("normalizes decoding inputs without duplicating raw fields in parsed resource entries", () => {
  const stored = { name: "a", parent: 0, flags: 0, payload: { offset: 20, size: 10 } };
  assert.deepEqual(resolveResourcePayload("Qt RCC", stored),
    { offset: 20, size: 10, compression: "none", uncompressedSize: 10 });
  assert.deepEqual(resolveResourcePayload("GLib GResource", stored),
    { offset: 20, size: 10, compression: "none", uncompressedSize: 10 });
  const compressed = { ...stored, flags: 1, payload: { ...stored.payload, uncompressedSize: 30 } };
  assert.deepEqual(resolveResourcePayload("Qt RCC", compressed),
    { offset: 20, size: 10, compression: "zlib", uncompressedSize: 30 });
  assert.deepEqual(resolveResourcePayload("GLib GResource", compressed),
    { offset: 20, size: 10, compression: "zlib", uncompressedSize: 30 });
  assert.deepEqual(resolveResourcePayload("Qt RCC", { ...compressed, flags: 4 }),
    { offset: 20, size: 10, compression: "zstd", uncompressedSize: 30 });
  assert.deepEqual(resolveResourcePayload("GLib GResource", { ...compressed, flags: 4 }),
    { offset: 20, size: 10, compression: "zlib", uncompressedSize: 30 });
  assert.equal(resolveResourcePayload("Qt RCC", { name: "dir", parent: null, flags: 2 }), null);
  assert.deepEqual(stored.payload, { offset: 20, size: 10 });
});
