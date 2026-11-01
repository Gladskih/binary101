"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";
import { createMemoryRangeReader } from "../../../../analyzers/memory-range-reader.js";
import {
  TEST_INTEGER, concatenateBytes, encodeCString, encodeSleb, encodeUint16,
  encodeUint64, encodeUleb
} from "../../../fixtures/dwarf-fixture-encoding.js";

const windowCursor = (bytes: Uint8Array, end = bytes.length, sectionOffset = 0) => {
  const source = createMemoryRangeReader(bytes);
  const reads: Array<{ offset: number; length: number }> = [];
  const issues: string[] = [];
  const cursor = new DwarfCursor({ ...source, read: (offset, length) => {
    reads.push({ offset, length });
    return source.read(offset, length);
  } }, { name: ".debug_info", offset: sectionOffset,
    size: Math.max(bytes.length - sectionOffset, end), compressed: false },
  0, end, true, issues);
  return { cursor, reads, issues };
};

void test("DwarfCursor reuses a local window across integers, LEB128 and strings", async () => {
  const bytes = Uint8Array.from(concatenateBytes(
    encodeUint16(TEST_INTEGER.uint16), encodeUleb(TEST_INTEGER.multibyteUleb),
    encodeSleb(TEST_INTEGER.negativeSleb), encodeCString("window"),
    encodeUint64(TEST_INTEGER.uint32)
  ));
  const { cursor, reads } = windowCursor(bytes);

  assert.equal(await cursor.uint16(), TEST_INTEGER.uint16);
  assert.equal(await cursor.uleb(), TEST_INTEGER.multibyteUleb);
  assert.equal(await cursor.sleb(), TEST_INTEGER.negativeSleb);
  assert.equal(await cursor.cstring(), "window");
  assert.equal(await cursor.uint64(), BigInt(TEST_INTEGER.uint32));
  assert.equal(cursor.position, bytes.length);
  assert.equal(reads.length, 1);
});

void test("DwarfCursor reads integers across windows and reuses backward seeks", async () => {
  // Exercise the 4 KiB local-window edge, independent of the shared reader cache.
  const bytes = new Uint8Array(8192);
  bytes.set([0x12, 0x34, 0x56], 4095);
  const { cursor, reads } = windowCursor(bytes);

  assert.equal(await cursor.uint8(), 0);
  cursor.position = 4095;
  assert.equal(await cursor.uint16(), 0x3412);
  assert.equal(await cursor.uint8(), 0x56);
  cursor.position = 4096;
  assert.equal(await cursor.unsigned(3), 0x5634n);
  assert.equal(reads.length, 3);
  assert.ok(reads.every(read => read.length <= 4097));
});

void test("DwarfCursor decodes LEB128 across a window without a 64-bit limit", async () => {
  const bytes = new Uint8Array(8192);
  const value = (1n << 100n) + 1n;
  const unsigned = encodeUleb(value);
  bytes.set(unsigned, 4095);
  bytes.set(encodeSleb(-value), 4095 + unsigned.length);
  const { cursor } = windowCursor(bytes);

  assert.equal(await cursor.uint8(), 0);
  cursor.position = 4095;
  assert.equal(await cursor.uleb(), value);
  assert.equal(await cursor.sleb(), -value);
});

void test("DwarfCursor refills after seeking behind the current window", async () => {
  const bytes = new Uint8Array(8192);
  bytes[0] = 0x12;
  const { cursor } = windowCursor(bytes);

  cursor.position = 4096;
  assert.equal(await cursor.uint8(), 0);
  cursor.position = 0;
  assert.equal(await cursor.uint8(), 0x12);
});

void test("DwarfCursor streams UTF-8 strings across windows and stops at the first NUL", async () => {
  const text = "a".repeat(4095) + "€" + "b".repeat(4096);
  const bytes = new TextEncoder().encode(text + "\0ignored\0");
  const { cursor } = windowCursor(bytes);

  assert.equal(await cursor.cstring(), text);
  assert.equal(cursor.position, new TextEncoder().encode(text).length + 1);
  assert.equal(await cursor.cstring(), "ignored");
});

void test("DwarfCursor flushes incomplete UTF-8 and handles empty strings", async () => {
  const { cursor } = windowCursor(Uint8Array.of(0, 0xe2, 0x82, 0));

  assert.equal(await cursor.cstring(), "");
  assert.equal(await cursor.cstring(), "�");
});

void test("DwarfCursor reports a missing NUL after multiple windows", async () => {
  const bytes = new Uint8Array(8192).fill(0x41);
  const { cursor, issues } = windowCursor(bytes);

  assert.equal(await cursor.cstring(), null);
  assert.equal(cursor.position, bytes.length);
  assert.deepEqual(issues, [".debug_info at 0x2000: Unterminated DWARF string."]);
});

void test("DwarfCursor clips later windows to its logical end before a NUL", async () => {
  const bytes = new Uint8Array(8192).fill(0x41);
  bytes[4097] = 0;
  const { cursor, reads, issues } = windowCursor(bytes, 4097);

  assert.equal(await cursor.cstring(), null);
  assert.deepEqual(reads, [{ offset: 0, length: 4096 }, { offset: 4096, length: 1 }]);
  assert.deepEqual(issues, [".debug_info at 0x1001: Unterminated DWARF string."]);
});

void test("DwarfCursor respects section, logical end and backing-view offsets", async () => {
  const backing = Uint8Array.of(0xff, 0xff, 0x7f, 0x41, 0, 0xff);
  const { cursor, reads, issues } = windowCursor(backing.subarray(1, 5), 1, 2);

  assert.equal(await cursor.cstring(), null);
  assert.deepEqual(reads, [{ offset: 2, length: 1 }]);
  assert.deepEqual(issues, [".debug_info at 0x1: Unterminated DWARF string."]);
});

void test("DwarfCursor consumes available short-prefetch bytes before reporting physical EOF", async () => {
  const { cursor, issues } = windowCursor(Uint8Array.of(0x41), 4);

  assert.equal(await cursor.uint8(), 0x41);
  assert.equal(await cursor.cstring(), null);
  assert.deepEqual(issues, [".debug_info at 0x1: File ended while reading 1 bytes."]);
});

void test("DwarfCursor copies blocks and accepts an empty block at the end", async () => {
  const bytes = Uint8Array.of(1, 2, 3);
  const { cursor } = windowCursor(bytes);
  const copy = await cursor.bytes(2n);

  assert.deepEqual(copy, Uint8Array.of(1, 2));
  assert.ok(copy);
  copy[0] = 0;
  cursor.position = 0;
  assert.equal(await cursor.uint8(), 1);
  assert.equal(cursor.skip(2), true);
  assert.deepEqual(await cursor.bytes(0), new Uint8Array(0));
});

void test("DwarfCursor rejects invalid block lengths and cannot read after failure", async () => {
  const { cursor, issues } = windowCursor(Uint8Array.of(1));

  assert.equal(await cursor.bytes(-1), null);
  assert.equal(await cursor.bytes(Number.NaN), null);
  assert.equal(await cursor.uint64(), null);
  assert.equal(await cursor.unsigned(16), null);
  assert.equal(await cursor.bytes(0), null);
  assert.deepEqual(issues, [".debug_info at 0x0: Invalid block length -1."]);
});

void test("DwarfCursor rejects invalid seeks even when it has a cached window", async () => {
  const { cursor, issues } = windowCursor(Uint8Array.of(1, 2));

  assert.equal(await cursor.uint8(), 1);
  cursor.position = -1;
  assert.equal(await cursor.uint8(), null);
  assert.deepEqual(issues, [".debug_info at 0x-1: Invalid DWARF cursor position."]);
});

void test("DwarfCursor rejects fractional seeks and does not reuse a poisoned window", async () => {
  const { cursor, issues } = windowCursor(Uint8Array.of(1, 2));

  assert.equal(await cursor.uint8(), 1);
  cursor.position = 0.5;
  assert.equal(await cursor.uleb(), null);
  cursor.position = 0;
  assert.equal(await cursor.sleb(), null);
  assert.equal(await cursor.cstring(), null);
  assert.equal(issues.length, 1);
});
