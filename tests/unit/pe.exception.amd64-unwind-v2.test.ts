"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AMD64_UNWIND_INFO_VERSION_1,
  ShortReadMockFile,
  UNW_FLAG_EHANDLER,
  createAmd64ExceptionFixtureWithSlots,
  createChainedAmd64ExceptionFixture,
  createTruncatedUnwindCodeArrayFixture,
  epilogPaddingSlot,
  epilogScopeSlot,
  parseAmd64ExceptionFixture,
  primaryUnwindCodeOffset,
  regularUnwindSlot,
  writePrimaryHandlerRva
} from "../helpers/pe-amd64-unwind-fixture.js";

void test("parseExceptionDirectory accepts AMD64 UNWIND_INFO version 2 epilog records", async () => {
  const parsed = await parseAmd64ExceptionFixture(createAmd64ExceptionFixtureWithSlots([
    epilogScopeSlot(),
    epilogPaddingSlot(),
    regularUnwindSlot(),
    regularUnwindSlot()
  ]));
  assert.ok(parsed);
  assert.strictEqual(parsed.unwindInfoVersion1Count, 0);
  assert.strictEqual(parsed.unwindInfoVersion2Count, 1);
  assert.strictEqual(parsed.epilogUnwindInfoCount, 1);
  assert.strictEqual(parsed.epilogScopeCount, 1);
  assert.ok(!parsed.issues.some(issue => issue.toLowerCase().includes("unexpected version")));
});

void test("parseExceptionDirectory reads handler tails after AMD64 UNWIND_INFO v2 slots", async () => {
  const fixture = createAmd64ExceptionFixtureWithSlots(
    [epilogScopeSlot(), epilogScopeSlot(), regularUnwindSlot()],
    { flags: UNW_FLAG_EHANDLER, trailingBytes: Uint32Array.BYTES_PER_ELEMENT }
  );
  writePrimaryHandlerRva(fixture, fixture.functionEndRva);
  const parsed = await parseAmd64ExceptionFixture(fixture);
  assert.ok(parsed);
  assert.deepEqual(parsed.handlerRvas, [fixture.functionEndRva]);
  assert.strictEqual(parsed.handlerUnwindInfoCount, 1);
  assert.strictEqual(parsed.epilogScopeCount, 2);
  assert.deepEqual(parsed.issues, []);
});

void test("parseExceptionDirectory reports truncated AMD64 UNWIND_INFO v2 code arrays", async () => {
  const parsed = await parseAmd64ExceptionFixture(createTruncatedUnwindCodeArrayFixture());
  assert.ok(parsed);
  assert.strictEqual(parsed.unwindInfoVersion2Count, 1);
  assert.ok(parsed.issues.some(issue => /truncated unwind-code array/i.test(issue)));
});

void test("parseExceptionDirectory reports late AMD64 UNWIND_INFO v2 epilog slots", async () => {
  const parsed = await parseAmd64ExceptionFixture(createAmd64ExceptionFixtureWithSlots([
    regularUnwindSlot(),
    epilogScopeSlot()
  ]));
  assert.ok(parsed);
  assert.strictEqual(parsed.epilogUnwindInfoCount, 0);
  assert.ok(parsed.issues.some(issue => /uop_epilog after regular unwind codes/i.test(issue)));
});

void test("parseExceptionDirectory accepts AMD64 UNWIND_INFO v2 without epilog records", async () => {
  const parsed = await parseAmd64ExceptionFixture(createAmd64ExceptionFixtureWithSlots([
    regularUnwindSlot()
  ]));
  assert.ok(parsed);
  assert.strictEqual(parsed.unwindInfoVersion2Count, 1);
  assert.strictEqual(parsed.epilogUnwindInfoCount, 0);
  assert.strictEqual(parsed.epilogScopeCount, 0);
  assert.deepEqual(parsed.issues, []);
});

void test("parseExceptionDirectory does not treat AMD64 UNWIND_INFO v1 opcode 6 as epilog", async () => {
  const parsed = await parseAmd64ExceptionFixture(createAmd64ExceptionFixtureWithSlots(
    [epilogScopeSlot()],
    { version: AMD64_UNWIND_INFO_VERSION_1 }
  ));
  assert.ok(parsed);
  assert.strictEqual(parsed.unwindInfoVersion1Count, 1);
  assert.strictEqual(parsed.epilogUnwindInfoCount, 0);
  assert.deepEqual(parsed.issues, []);
});

void test("parseExceptionDirectory reports short reads of AMD64 UNWIND_INFO v2 code arrays", async () => {
  const fixture = createAmd64ExceptionFixtureWithSlots([
    epilogScopeSlot(),
    regularUnwindSlot()
  ]);
  const parsed = await parseAmd64ExceptionFixture(
    fixture,
    new ShortReadMockFile(
      fixture.bytes,
      "exception-unwind-v2-short-read.bin",
      primaryUnwindCodeOffset(fixture)
    )
  );
  assert.ok(parsed);
  assert.strictEqual(parsed.unwindInfoVersion2Count, 1);
  assert.ok(parsed.issues.some(issue => /truncated unwind-code array/i.test(issue)));
});

void test("parseExceptionDirectory follows chained AMD64 UNWIND_INFO v2 blocks", async () => {
  const parsed = await parseAmd64ExceptionFixture(createChainedAmd64ExceptionFixture([
    epilogScopeSlot()
  ]));
  assert.ok(parsed);
  assert.strictEqual(parsed.uniqueUnwindInfoCount, 2);
  assert.strictEqual(parsed.unwindInfoVersion2Count, 2);
  assert.strictEqual(parsed.chainedUnwindInfoCount, 1);
  assert.strictEqual(parsed.epilogScopeCount, 1);
  assert.deepEqual(parsed.issues, []);
});

void test("parseExceptionDirectory ignores leading AMD64 UNWIND_INFO v2 epilog padding slots", async () => {
  const parsed = await parseAmd64ExceptionFixture(createAmd64ExceptionFixtureWithSlots([
    epilogPaddingSlot()
  ]));
  assert.ok(parsed);
  assert.strictEqual(parsed.unwindInfoVersion2Count, 1);
  assert.strictEqual(parsed.epilogUnwindInfoCount, 0);
  assert.strictEqual(parsed.epilogScopeCount, 0);
  assert.deepEqual(parsed.issues, []);
});
