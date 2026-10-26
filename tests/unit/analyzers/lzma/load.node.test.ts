import assert from "node:assert/strict";
import { test } from "node:test";
import { loadLzmaDecoder } from "../../../../analyzers/lzma/load.node.js";
import { lzmaData, lzmaProperties } from "../../../fixtures/lzma.js";

void test("Node loads the installed local WASM and decodes raw bytes", async () => {
  const decoder = await loadLzmaDecoder();

  assert.deepEqual(decoder.decodeLzma(lzmaData, Uint8Array.from(lzmaProperties), 4),
    { data: new TextEncoder().encode("DATA"), bytesRead: 14, resultCode: 0, status: 1 });
});
