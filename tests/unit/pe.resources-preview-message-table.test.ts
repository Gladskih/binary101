"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeMessageTablePreview } from "../../analyzers/pe/resources/preview/message-table.js";
import { expectDefined } from "../helpers/expect-defined.js";

// MESSAGE_RESOURCE_DATA stores a DWORD block count before the first MESSAGE_RESOURCE_BLOCK.
const MESSAGE_RESOURCE_DATA_HEADER_SIZE = Uint32Array.BYTES_PER_ELEMENT;
const MESSAGE_RESOURCE_BLOCK_SIZE = 12; // MESSAGE_RESOURCE_BLOCK
const MESSAGE_RESOURCE_ENTRY_HEADER_SIZE = 4; // Length + Flags before the message bytes.
const MESSAGE_RESOURCE_ANSI_FLAGS = 0;
// Windows ANSI Latin-1 code page used by many PE string resources.
const WINDOWS_1252_CODE_PAGE = 1252;

const buildSingleAnsiMessageTable = (
  messageId: number,
  messageBytes: number[]
): Uint8Array => {
  const entryOffset = MESSAGE_RESOURCE_DATA_HEADER_SIZE + MESSAGE_RESOURCE_BLOCK_SIZE;
  const entryLength = MESSAGE_RESOURCE_ENTRY_HEADER_SIZE + messageBytes.length;
  const bytes = new Uint8Array(entryOffset + entryLength).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 1, true); // NumberOfBlocks
  view.setUint32(4, messageId, true); // LowId
  view.setUint32(8, messageId, true); // HighId
  view.setUint32(12, entryOffset, true); // OffsetToEntries
  view.setUint16(entryOffset, entryLength, true);
  view.setUint16(entryOffset + 2, MESSAGE_RESOURCE_ANSI_FLAGS, true);
  bytes.set(messageBytes, entryOffset + MESSAGE_RESOURCE_ENTRY_HEADER_SIZE);
  return bytes;
};

void test("decodeMessageTablePreview uses the declared resource code page for ANSI entries", () => {
  const preview = expectDefined(decodeMessageTablePreview(
    buildSingleAnsiMessageTable(10, [0xe9]),
    WINDOWS_1252_CODE_PAGE
  ));

  assert.deepEqual(preview.messages, [{ id: 10, strings: [String.fromCharCode(0x00e9)] }]);
  assert.deepStrictEqual(preview.issues, []);
  assert.strictEqual(preview.truncated, false);
});

void test("decodeMessageTablePreview warns instead of silently falling back to UTF-8", () => {
  // 0xc3 0xa9 is valid UTF-8 for "é". Unsupported-codepage handling must not silently accept that.
  const preview = expectDefined(decodeMessageTablePreview(
    buildSingleAnsiMessageTable(20, [0xc3, 0xa9]),
    0
  ));

  assert.match(preview.issues.join(" "), /supported code page/i);
  assert.notStrictEqual(preview.messages[0]?.strings[0], String.fromCharCode(0x00e9));
  assert.strictEqual(preview.truncated, false);
});

void test("decodeMessageTablePreview preserves significant leading and trailing whitespace", () => {
  const preview = expectDefined(decodeMessageTablePreview(
    buildSingleAnsiMessageTable(30, [0x20, 0x20, 0x41, 0x0d, 0x0a]),
    WINDOWS_1252_CODE_PAGE
  ));

  assert.deepEqual(preview.messages, [{ id: 30, strings: ["  A\r\n"] }]);
  assert.deepStrictEqual(preview.issues, []);
  assert.strictEqual(preview.truncated, false);
});

void test("decodeMessageTablePreview decodes ANSI entries with Windows code page 932", () => {
  const preview = expectDefined(decodeMessageTablePreview(
    buildSingleAnsiMessageTable(40, [0x82, 0xa0]),
    932 // Windows Shift_JIS code page
  ));

  assert.deepEqual(preview.messages, [{ id: 40, strings: ["\u3042"] }]);
  assert.deepStrictEqual(preview.issues, []);
  assert.strictEqual(preview.truncated, false);
});
