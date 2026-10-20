import assert from "node:assert/strict";
import { test } from "node:test";
import { deflateRawSync } from "node:zlib";
import { inflateEmbeddedDebugImage } from "../../../../../analyzers/pe/debug/embedded-debug-image.js";
import { MockFile } from "../../../../helpers/mock-file.js";

void test("embedded PDB inflates raw Deflate and checks the actual output size", async () => {
  const bytes = new TextEncoder().encode("portable metadata");
  const compressed = deflateRawSync(bytes);
  const result = await inflateEmbeddedDebugImage(new MockFile(compressed), bytes.length);

  assert.deepEqual(await result.readBytes(0, result.size), bytes);
});

void test("embedded PDB rejects expansion beyond declared size", async () => {
  await assert.rejects(inflateEmbeddedDebugImage(new MockFile(deflateRawSync("too long")), 1),
    /exceeds declared/i);
});

void test("embedded PDB rejects short output and corrupt input", async () => {
  await assert.rejects(inflateEmbeddedDebugImage(new MockFile(deflateRawSync("a")), 2), /does not match/i);
  await assert.rejects(inflateEmbeddedDebugImage(new MockFile(Uint8Array.from([0xff])), 1));
});

void test("embedded PDB rejects short compressed reads without consuming unrelated bytes", async () => {
  await assert.rejects(inflateEmbeddedDebugImage({ size: 8,
    readBytes: async () => Uint8Array.of(0) }, 1), /compressed debug stream is truncated/);
});
