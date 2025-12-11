"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePeHeaders } from "../../analyzers/pe/core.js";
import { MockFile } from "../helpers/mock-file.js";

void test("parsePeHeaders returns null when e_lfanew points past file end", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x5a4d, true);
  view.setUint32(0x3c, 200, true);
  const parsed = await parsePeHeaders(new MockFile(bytes, "bad-e_lfanew.exe"));
  assert.strictEqual(parsed, null);
});

void test("parsePeHeaders returns null when PE signature is missing", async () => {
  const bytes = new Uint8Array(256).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x5a4d, true);
  const peOffset = 0x80;
  view.setUint32(0x3c, peOffset, true);
  bytes.set([0x50, 0x58, 0, 0], peOffset);
  const parsed = await parsePeHeaders(new MockFile(bytes, "bad-pe-sig.exe"));
  assert.strictEqual(parsed, null);
});

