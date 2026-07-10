"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";
import {
  TEST_DWARF,
  TEST_INTEGER,
  concatenateBytes,
  encodeBigEndianUnsigned,
  encodeCString,
  encodeLebTerminatedAfter,
  encodeSequence,
  encodeSleb,
  encodeText,
  encodeUint8,
  encodeUint16,
  encodeUint32,
  encodeUint64,
  encodeUnterminatedLeb,
  encodeUleb
} from "../../../fixtures/dwarf-fixture-encoding.js";
import { MockFile } from "../../../helpers/mock-file.js";

// LEB128 byte sequences are independent test oracles for DWARF 5 section 7.6:
// https://dwarfstd.org/doc/DWARF5.pdf

const createCursor = (bytes: number[], issues: string[] = []): DwarfCursor =>
  new DwarfCursor(
    new MockFile(Uint8Array.from(bytes)),
    { name: ".debug_info", offset: 0, size: bytes.length, compressed: false },
    0,
    bytes.length,
    true,
    issues
  );

const createBigEndianCursor = (bytes: number[]): DwarfCursor => new DwarfCursor(
  new MockFile(Uint8Array.from(bytes)),
  { name: ".debug_info", offset: 0, size: bytes.length, compressed: false },
  0,
  bytes.length,
  false,
  []
);

void test("DwarfCursor reads fixed-width integers in both byte orders", async () => {
  const little = createCursor(concatenateBytes(
    encodeUint16(TEST_INTEGER.uint16),
    encodeUint32(TEST_INTEGER.uint32)
  ));
  const big = createBigEndianCursor(concatenateBytes(
    encodeBigEndianUnsigned(TEST_INTEGER.uint16, Uint16Array.BYTES_PER_ELEMENT),
    encodeBigEndianUnsigned(TEST_INTEGER.uint32, Uint32Array.BYTES_PER_ELEMENT)
  ));

  assert.equal(await little.uint16(), TEST_INTEGER.uint16);
  assert.equal(await little.uint32(), TEST_INTEGER.uint32);
  assert.equal(await big.uint16(), TEST_INTEGER.uint16);
  assert.equal(await big.uint32(), TEST_INTEGER.uint32);
});

void test("DwarfCursor reads unsigned, signed, and unsigned LEB128 values", async () => {
  const cursor = createCursor(concatenateBytes(
    encodeUleb(TEST_INTEGER.multibyteUleb),
    encodeSleb(TEST_INTEGER.negativeSleb),
    encodeUint32(TEST_INTEGER.uint32)
  ));

  assert.equal(await cursor.uleb(), TEST_INTEGER.multibyteUleb);
  assert.equal(await cursor.sleb(), TEST_INTEGER.negativeSleb);
  assert.equal(await cursor.unsigned(4), BigInt(TEST_INTEGER.uint32));
});

void test("DwarfCursor reads every supported generic integer width", async () => {
  const cursor = createCursor(concatenateBytes(
    encodeUint8(TEST_INTEGER.uint8),
    encodeUint16(TEST_INTEGER.uint16),
    encodeUint32(TEST_INTEGER.uint32),
    encodeUint64(TEST_DWARF.flag.present)
  ));

  assert.equal(
    await cursor.unsigned(Uint8Array.BYTES_PER_ELEMENT),
    BigInt(TEST_INTEGER.uint8)
  );
  assert.equal(
    await cursor.unsigned(Uint16Array.BYTES_PER_ELEMENT),
    BigInt(TEST_INTEGER.uint16)
  );
  assert.equal(
    await cursor.unsigned(Uint32Array.BYTES_PER_ELEMENT),
    BigInt(TEST_INTEGER.uint32)
  );
  assert.equal(
    await cursor.unsigned(BigUint64Array.BYTES_PER_ELEMENT),
    BigInt(TEST_DWARF.flag.present)
  );
});

void test("DwarfCursor decodes multi-byte signed LEB128 values", async () => {
  const cursor = createCursor(concatenateBytes(
    encodeSleb(TEST_INTEGER.multibyteUleb),
    encodeSleb(-TEST_INTEGER.multibyteUleb)
  ));

  assert.equal(await cursor.sleb(), TEST_INTEGER.multibyteUleb);
  assert.equal(await cursor.sleb(), -TEST_INTEGER.multibyteUleb);
});

void test("DwarfCursor reports truncated and unsupported reads once", async () => {
  const issues: string[] = [];
  const cursor = createCursor(encodeSequence(Uint8Array.BYTES_PER_ELEMENT), issues);

  assert.equal(await cursor.uint16(), null);
  assert.equal(await cursor.unsigned(3), null);
  assert.equal(cursor.failed, true);
  assert.equal(issues.length, 1);
});

void test("DwarfCursor bounds skips and rejects overlong LEB128", async () => {
  const issues: string[] = [];
  const cursor = createCursor(
    encodeUnterminatedLeb(TEST_DWARF.limits.maximumLebBytes + 1),
    issues
  );

  assert.equal(await cursor.uleb(), null);
  assert.equal(cursor.skip(1), false);
  assert.ok(issues[0]?.includes("exceeds 10 bytes"));
});

void test("DwarfCursor rejects a ULEB128 terminator beyond its tenth byte", async () => {
  const issues: string[] = [];
  const cursor = createCursor(
    encodeLebTerminatedAfter(TEST_DWARF.limits.maximumLebBytes),
    issues
  );

  assert.equal(await cursor.uleb(), null);
  assert.equal(cursor.position, cursor.end);
  assert.ok(issues[0]?.includes("exceeds 10 bytes"));
});

void test("DwarfCursor advances valid skips and accepts the exact remaining length", () => {
  const cursor = createCursor(encodeSequence(
    Uint8Array.BYTES_PER_ELEMENT + Uint16Array.BYTES_PER_ELEMENT
  ));

  assert.equal(cursor.skip(Uint8Array.BYTES_PER_ELEMENT), true);
  assert.equal(cursor.position, Uint8Array.BYTES_PER_ELEMENT);
  assert.equal(cursor.skip(BigInt(Uint16Array.BYTES_PER_ELEMENT)), true);
  assert.equal(
    cursor.position,
    Uint8Array.BYTES_PER_ELEMENT + Uint16Array.BYTES_PER_ELEMENT
  );
});

void test("DwarfCursor rejects unsafe, negative, and out-of-range skips", () => {
  const unsafeIssues: string[] = [];
  const negativeIssues: string[] = [];
  const rangeIssues: string[] = [];

  const oneByte = encodeSequence(Uint8Array.BYTES_PER_ELEMENT);

  assert.equal(createCursor(oneByte, unsafeIssues).skip(Number.NaN), false);
  assert.equal(createCursor(oneByte, negativeIssues).skip(-1), false);
  assert.equal(
    createCursor(oneByte, rangeIssues).skip(Uint16Array.BYTES_PER_ELEMENT),
    false
  );
  assert.ok(unsafeIssues[0]?.includes("Cannot skip NaN bytes"));
  assert.ok(negativeIssues[0]?.includes("Cannot skip -1 bytes"));
  assert.ok(rangeIssues[0]?.includes(
    `Cannot skip ${Uint16Array.BYTES_PER_ELEMENT} bytes`
  ));
});

void test("DwarfCursor decodes strings and reports unterminated strings", async () => {
  const valid = createCursor(encodeCString("hi"));
  const issues: string[] = [];
  const invalid = createCursor(encodeText("hi"), issues);

  assert.equal(await valid.cstring(), "hi");
  assert.equal(valid.failed, false);
  assert.equal(await invalid.cstring(), null);
  assert.ok(issues[0]?.includes("Unterminated"));
});

void test("DwarfCursor truncates exceptionally long displayed strings with a notice", async () => {
  const issues: string[] = [];
  const cursor = createCursor(encodeCString(
    "a".repeat(TEST_DWARF.limits.displayedStringBytes + Uint32Array.BYTES_PER_ELEMENT)
  ), issues);

  const value = await cursor.cstring();

  assert.equal(value?.length, TEST_DWARF.limits.displayedStringBytes);
  assert.ok(issues[0]?.includes(`truncated to ${TEST_DWARF.limits.displayedStringBytes}`));
});

void test("DwarfCursor enforces an end below the containing section size", async () => {
  const issues: string[] = [];
  const bytes = encodeSequence(
    Uint8Array.BYTES_PER_ELEMENT + Uint16Array.BYTES_PER_ELEMENT
  );
  const file = new MockFile(Uint8Array.from(bytes));
  const cursor = new DwarfCursor(
    file,
    { name: ".debug_info", offset: 0, size: bytes.length, compressed: false },
    0,
    Uint8Array.BYTES_PER_ELEMENT,
    true,
    issues
  );

  assert.equal(await cursor.uint8(), 1);
  assert.equal(await cursor.uint8(), null);
  assert.ok(issues[0]?.includes("Truncated value needs 1 bytes"));
});

void test("DwarfCursor handles file reads shorter than the declared section range", async () => {
  const issues: string[] = [];
  const cursor = new DwarfCursor(
    {
      size: Uint16Array.BYTES_PER_ELEMENT,
      read: async () => new DataView(new ArrayBuffer(1)),
      readBytes: async () => new Uint8Array(1)
    },
    {
      name: ".debug_info",
      offset: 0,
      size: Uint16Array.BYTES_PER_ELEMENT,
      compressed: false
    },
    0,
    Uint16Array.BYTES_PER_ELEMENT,
    true,
    issues
  );

  assert.equal(await cursor.uint16(), null);
  assert.ok(issues[0]?.includes("File ended while reading 2 bytes"));
});
