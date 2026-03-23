"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { enrichResourcePreviews } from "../../analyzers/pe/resources-preview.js";
import { MockFile } from "../helpers/mock-file.js";
import type { ResourceTree } from "../../analyzers/pe/resources-core.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();
const RESOURCE_DIRECTORY_HEADER_SIZE = 16; // IMAGE_RESOURCE_DIRECTORY
const MESSAGE_RESOURCE_BLOCK_SIZE = 12; // MESSAGE_RESOURCE_BLOCK
const MESSAGE_RESOURCE_ENTRY_HEADER_SIZE = 4; // Length + Flags before the text payload.
const STRING_TABLE_ENTRY_COUNT = 16; // One STRINGTABLE block stores exactly 16 entries.
const UTF16_CODE_PAGE = 1200; // Unicode code page used by PE string resources.

const writeUtf16 = (bytes: Uint8Array, offset: number, text: string): void => {
  for (let index = 0; index < text.length; index += 1) {
    const codePoint = text.charCodeAt(index);
    bytes[offset + index * 2] = codePoint & 0xff;
    bytes[offset + index * 2 + 1] = codePoint >>> 8;
  }
};

const createIdentityResourceTree = (
  typeName: string,
  dataRva: number,
  size: number,
  lang: number,
  codePage: number
): ResourceTree => {
  const directoryBuffer = new ArrayBuffer(RESOURCE_DIRECTORY_HEADER_SIZE);
  return {
    base: 0,
    limitEnd: directoryBuffer.byteLength,
    top: [],
    detail: [
      {
        typeName,
        entries: [
          {
            id: 1,
            name: null,
            langs: [{ lang, size, codePage, dataRVA: dataRva, reserved: 0 }]
          }
        ]
      }
    ],
    view: async (off: number, len: number) => new DataView(directoryBuffer, off, len),
    rvaToOff: value => value
  };
};

const buildMessageTable = (
  firstMessageId: number,
  ansiText: string,
  unicodeText: string
): Uint8Array => {
  const ansiBytes = encoder.encode(ansiText);
  const unicodeBytes = new Uint8Array(unicodeText.length * 2);
  writeUtf16(unicodeBytes, 0, unicodeText);
  const blockOffset = Uint32Array.BYTES_PER_ELEMENT + MESSAGE_RESOURCE_BLOCK_SIZE;
  const firstEntrySize = MESSAGE_RESOURCE_ENTRY_HEADER_SIZE + ansiBytes.length;
  const secondEntryOffset = blockOffset + firstEntrySize;
  const secondEntrySize = MESSAGE_RESOURCE_ENTRY_HEADER_SIZE + unicodeBytes.length;
  const bytes = new Uint8Array(secondEntryOffset + secondEntrySize).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 1, true); // NumberOfBlocks
  view.setUint32(4, firstMessageId, true); // LowId
  view.setUint32(8, firstMessageId + 1, true); // HighId
  view.setUint32(12, blockOffset, true); // OffsetToEntries from the start of the resource
  view.setUint16(blockOffset, firstEntrySize, true);
  view.setUint16(blockOffset + 2, 0, true); // ANSI entry
  bytes.set(ansiBytes, blockOffset + MESSAGE_RESOURCE_ENTRY_HEADER_SIZE);
  view.setUint16(secondEntryOffset, secondEntrySize, true);
  view.setUint16(secondEntryOffset + 2, 1, true); // Unicode entry
  bytes.set(unicodeBytes, secondEntryOffset + MESSAGE_RESOURCE_ENTRY_HEADER_SIZE);
  return bytes;
};

const buildSingleCodeUnitStringTable = (entryCount: number): Uint8Array => {
  const bytes = new Uint8Array(entryCount * 4).fill(0);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < entryCount; index += 1) {
    const entryOffset = index * 4;
    view.setUint16(entryOffset, 1, true);
    writeUtf16(bytes, entryOffset + Uint16Array.BYTES_PER_ELEMENT, String.fromCharCode(0x41 + index));
  }
  return bytes;
};

void test("enrichResourcePreviews decodes MESSAGE_RESOURCE_DATA blocks using block offsets and entry lengths", async () => {
  const firstMessageId = 10;
  const messageTableBytes = buildMessageTable(firstMessageId, "OK", "Hi");
  const messageTableOffset = RESOURCE_DIRECTORY_HEADER_SIZE;
  const fileBytes = new Uint8Array(messageTableOffset + messageTableBytes.length).fill(0);
  fileBytes.set(messageTableBytes, messageTableOffset);
  // 2057 = en-GB; any non-null LANGID is fine, this one is just explicit.
  const tree = createIdentityResourceTree("MESSAGETABLE", messageTableOffset, messageTableBytes.length, 2057, 0);

  const result = await enrichResourcePreviews(new MockFile(fileBytes), tree);
  const group = expectDefined(result.detail[0]);
  const entry = expectDefined(group.entries[0]);
  const lang = expectDefined(entry.langs[0]);
  assert.strictEqual(lang.previewKind, "messageTable");
  assert.deepEqual(lang.messageTable, {
    messages: [
      { id: firstMessageId, strings: ["OK"] },
      { id: firstMessageId + 1, strings: ["Hi"] }
    ],
    truncated: false
  });
});

void test("enrichResourcePreviews limits STRING resources to one 16-string block", async () => {
  const entryCount = STRING_TABLE_ENTRY_COUNT + 1; // Deliberately 16 + 1 entries to catch over-read past one block.
  const stringTableBytes = buildSingleCodeUnitStringTable(entryCount);
  const stringTableOffset = RESOURCE_DIRECTORY_HEADER_SIZE;
  const fileBytes = new Uint8Array(stringTableOffset + stringTableBytes.length).fill(0);
  fileBytes.set(stringTableBytes, stringTableOffset);
  // 1031 = de-DE; codePage 1200 matches UTF-16LE string tables.
  const tree = createIdentityResourceTree(
    "STRING",
    stringTableOffset,
    stringTableBytes.length,
    1031,
    UTF16_CODE_PAGE
  );

  const result = await enrichResourcePreviews(new MockFile(fileBytes), tree);
  const group = expectDefined(result.detail[0]);
  const entry = expectDefined(group.entries[0]);
  const lang = expectDefined(entry.langs[0]);
  const stringTable = expectDefined(lang.stringTable);
  assert.strictEqual(lang.previewKind, "stringTable");
  // Microsoft Learn, STRINGTABLE/LoadString:
  // each string resource block stores at most 16 counted strings.
  assert.equal(stringTable.length, STRING_TABLE_ENTRY_COUNT);
  assert.ok(stringTable.every(item => item.id == null || item.id < STRING_TABLE_ENTRY_COUNT));
});

void test("enrichResourcePreviews preserves embedded NUL code units in counted STRING entries", async () => {
  const stringTableOffset = RESOURCE_DIRECTORY_HEADER_SIZE;
  const stringTableBytes = new Uint8Array(8).fill(0);
  const view = new DataView(stringTableBytes.buffer);
  view.setUint16(0, 3, true);
  // Win32 string-table entries are counted UTF-16 strings, not NUL-terminated strings.
  writeUtf16(stringTableBytes, 2, "A\0B");
  const fileBytes = new Uint8Array(stringTableOffset + stringTableBytes.length).fill(0);
  fileBytes.set(stringTableBytes, stringTableOffset);
  const tree = createIdentityResourceTree(
    "STRING",
    stringTableOffset,
    stringTableBytes.length,
    1033,
    UTF16_CODE_PAGE
  );

  const result = await enrichResourcePreviews(new MockFile(fileBytes), tree);
  const group = expectDefined(result.detail[0]);
  const entry = expectDefined(group.entries[0]);
  const lang = expectDefined(entry.langs[0]);
  const stringTable = expectDefined(lang.stringTable);
  const firstString = expectDefined(stringTable[0]);

  assert.strictEqual(firstString.text.length, 3);
  assert.strictEqual(firstString.text.charCodeAt(0), 0x41);
  assert.strictEqual(firstString.text.charCodeAt(1), 0x0000);
  assert.strictEqual(firstString.text.charCodeAt(2), 0x42);
});
