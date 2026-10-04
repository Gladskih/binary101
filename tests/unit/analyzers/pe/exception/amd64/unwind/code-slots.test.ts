"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  analyzeAmd64UnwindCodeSlots
} from "../../../../../../../analyzers/pe/exception/amd64/unwind-code-slots.js";
import { MockFile } from "../../../../../../helpers/mock-file.js";
import {
  AMD64_UNWIND_INFO_VERSION_1,
  AMD64_UNWIND_INFO_VERSION_2,
  createAmd64ExceptionFixtureWithSlots,
  createTruncatedUnwindCodeArrayFixture,
  epilogPaddingSlot,
  epilogScopeSlot,
  regularUnwindSlot
} from "../../../../../../helpers/pe-amd64-unwind-fixture.js";

void test("analyzeAmd64UnwindCodeSlots counts leading v2 epilog scopes", async () => {
  const fixture = createAmd64ExceptionFixtureWithSlots([
    epilogScopeSlot(),
    epilogPaddingSlot(),
    regularUnwindSlot()
  ]);
  const analysis = await analyzeAmd64UnwindCodeSlots(
    new MockFile(fixture.bytes, "amd64-unwind-code-slots.bin"),
    fixture.primaryUnwindRva,
    fixture.primaryUnwindCodeCount,
    AMD64_UNWIND_INFO_VERSION_2
  );
  assert.deepEqual(analysis, {
    epilogScopeCount: 1,
    hasEpilogInfo: true,
    hasLateEpilogCode: false,
    isTruncated: false
  });
});

void test("analyzeAmd64UnwindCodeSlots flags v2 epilog codes after regular codes", async () => {
  const fixture = createAmd64ExceptionFixtureWithSlots([
    regularUnwindSlot(),
    epilogScopeSlot()
  ]);
  const analysis = await analyzeAmd64UnwindCodeSlots(
    new MockFile(fixture.bytes, "amd64-unwind-code-slots-late.bin"),
    fixture.primaryUnwindRva,
    fixture.primaryUnwindCodeCount,
    AMD64_UNWIND_INFO_VERSION_2
  );
  assert.deepEqual(analysis, {
    epilogScopeCount: 0,
    hasEpilogInfo: false,
    hasLateEpilogCode: true,
    isTruncated: false
  });
});

void test("analyzeAmd64UnwindCodeSlots skips regular unwind operand slots", async () => {
  const fixture = createAmd64ExceptionFixtureWithSlots([
    epilogScopeSlot(),
    // Microsoft x64 UWOP_SAVE_NONVOL (4) consumes the following slot as a frame
    // offset operand; the operand's low nibble can equal UOP_Epilog (6).
    [0x13, 0x34],
    [0x0a, 0x06],
    regularUnwindSlot()
  ]);
  const analysis = await analyzeAmd64UnwindCodeSlots(
    new MockFile(fixture.bytes, "amd64-unwind-code-slots-operands.bin"),
    fixture.primaryUnwindRva,
    fixture.primaryUnwindCodeCount,
    AMD64_UNWIND_INFO_VERSION_2
  );
  assert.deepEqual(analysis, {
    epilogScopeCount: 1,
    hasEpilogInfo: true,
    hasLateEpilogCode: false,
    isTruncated: false
  });
});

void test("analyzeAmd64UnwindCodeSlots ignores opcode 6 for version 1 blocks", async () => {
  const fixture = createAmd64ExceptionFixtureWithSlots([epilogScopeSlot()]);
  const analysis = await analyzeAmd64UnwindCodeSlots(
    new MockFile(fixture.bytes, "amd64-unwind-code-slots-v1.bin"),
    fixture.primaryUnwindRva,
    fixture.primaryUnwindCodeCount,
    AMD64_UNWIND_INFO_VERSION_1
  );
  assert.deepEqual(analysis, {
    epilogScopeCount: 0,
    hasEpilogInfo: false,
    hasLateEpilogCode: false,
    isTruncated: false
  });
});

void test("analyzeAmd64UnwindCodeSlots reports physically truncated code arrays", async () => {
  const fixture = createTruncatedUnwindCodeArrayFixture();
  const analysis = await analyzeAmd64UnwindCodeSlots(
    new MockFile(fixture.bytes, "amd64-unwind-code-slots-truncated.bin"),
    fixture.primaryUnwindRva,
    fixture.primaryUnwindCodeCount,
    AMD64_UNWIND_INFO_VERSION_2
  );
  assert.deepEqual(analysis, {
    epilogScopeCount: 0,
    hasEpilogInfo: false,
    hasLateEpilogCode: false,
    isTruncated: true
  });
});

// Operand counts from Microsoft's x64 exception handling, "Unwind operation code":
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-unwind_code
const operandOperations = [
  { name: "ALLOC_LARGE (OpInfo=0)", operationByte: 0x01, operandCount: 1 },
  { name: "ALLOC_LARGE (OpInfo=1)", operationByte: 0x11, operandCount: 2 },
  { name: "SAVE_NONVOL", operationByte: 0x34, operandCount: 1 },
  { name: "SAVE_NONVOL_FAR", operationByte: 0x35, operandCount: 2 },
  { name: "SAVE_XMM128", operationByte: 0x68, operandCount: 1 },
  { name: "SAVE_XMM128_FAR", operationByte: 0x69, operandCount: 2 }
];

for (const version of [AMD64_UNWIND_INFO_VERSION_1, AMD64_UNWIND_INFO_VERSION_2]) {
  for (const { name, operationByte, operandCount } of operandOperations) {
    for (let suppliedOperands = 0; suppliedOperands < operandCount; suppliedOperands += 1) {
      void test(`v${version} flags ${name} with ${suppliedOperands} operand slots`, async () => {
        const fixture = createAmd64ExceptionFixtureWithSlots([
          regularUnwindSlot(),
          [1, operationByte],
          ...Array.from({ length: suppliedOperands }, () => epilogScopeSlot())
        ], { version });
        const analysis = await analyzeAmd64UnwindCodeSlots(
          new MockFile(fixture.bytes, "missing-unwind-operands.bin"),
          fixture.primaryUnwindRva,
          fixture.primaryUnwindCodeCount,
          version
        );
        assert.strictEqual(analysis.isTruncated, true);
        assert.strictEqual(analysis.hasLateEpilogCode, false);
      });
    }

    void test(`v${version} accepts ${name} ending exactly at CountOfCodes`, async () => {
      const fixture = createAmd64ExceptionFixtureWithSlots([
        regularUnwindSlot(),
        [1, operationByte],
        ...Array.from({ length: operandCount }, () => epilogScopeSlot())
      ], { version });
      const analysis = await analyzeAmd64UnwindCodeSlots(
        new MockFile(fixture.bytes, "complete-unwind-operands.bin"),
        fixture.primaryUnwindRva,
        fixture.primaryUnwindCodeCount,
        version
      );
      assert.strictEqual(analysis.isTruncated, false);
      assert.strictEqual(analysis.epilogScopeCount, 0);
      assert.strictEqual(analysis.hasLateEpilogCode, false);
    });
  }
}

void test("v2 preserves epilog scopes when a later operation lacks operands", async () => {
  const fixture = createAmd64ExceptionFixtureWithSlots([
    epilogScopeSlot(), regularUnwindSlot(), epilogScopeSlot(),
    // UWOP_ALLOC_LARGE OpInfo=1 needs two operand slots (Microsoft x64 EH).
    [1, 0x11]
  ]);
  const analysis = await analyzeAmd64UnwindCodeSlots(
    new MockFile(fixture.bytes, "late-epilog-and-missing-operands.bin"),
    fixture.primaryUnwindRva,
    fixture.primaryUnwindCodeCount,
    AMD64_UNWIND_INFO_VERSION_2
  );
  assert.deepEqual(analysis, {
    epilogScopeCount: 1,
    hasEpilogInfo: true,
    hasLateEpilogCode: true,
    isTruncated: true
  });
});

void test("v2 counts epilog scopes with either offset byte nonzero", async () => {
  const fixture = createAmd64ExceptionFixtureWithSlots([
    epilogScopeSlot(1, 0), epilogScopeSlot(0, 1), epilogPaddingSlot()
  ]);
  const analysis = await analyzeAmd64UnwindCodeSlots(
    new MockFile(fixture.bytes, "epilog-offset-bytes.bin"),
    fixture.primaryUnwindRva,
    fixture.primaryUnwindCodeCount,
    AMD64_UNWIND_INFO_VERSION_2
  );
  assert.strictEqual(analysis.epilogScopeCount, 2);
});

for (const offset of [-1, 0, 1]) {
  void test(`rejects an out-of-bounds code array at offset ${offset} before reading`, async () => {
    const analysis = await analyzeAmd64UnwindCodeSlots(
      {
        // A four-byte header plus a two-byte slot cannot fit in five bytes.
        size: 5,
        read: () => { assert.fail("Out-of-bounds arrays must not be read"); },
        readBytes: () => { assert.fail("Out-of-bounds arrays must not be read"); }
      },
      offset, 1, AMD64_UNWIND_INFO_VERSION_1
    );
    assert.strictEqual(analysis.isTruncated, true);
  });
}

void test("empty arrays do not read the file or report truncation", async () => {
  const analysis = await analyzeAmd64UnwindCodeSlots(
    {
      size: 0,
      read: () => { assert.fail("Empty arrays must not be read"); },
      readBytes: () => { assert.fail("Empty arrays must not be read"); }
    },
    0, 0, AMD64_UNWIND_INFO_VERSION_1
  );
  assert.deepEqual(analysis, {
    epilogScopeCount: 0,
    hasEpilogInfo: false,
    hasLateEpilogCode: false,
    isTruncated: false
  });
});

void test("unknown versions receive physical bounds checks without opcode interpretation", async () => {
  const fixture = createAmd64ExceptionFixtureWithSlots([[1, 0x11]], { version: 0 });
  const analysis = await analyzeAmd64UnwindCodeSlots(
    new MockFile(fixture.bytes, "unknown-unwind-version.bin"),
    fixture.primaryUnwindRva,
    fixture.primaryUnwindCodeCount,
    0
  );
  assert.strictEqual(analysis.isTruncated, false);
  assert.strictEqual(analysis.epilogScopeCount, 0);
});

void test("accepts an array ending exactly at EOF", async () => {
  const fixture = createAmd64ExceptionFixtureWithSlots([regularUnwindSlot()]);
  const analysis = await analyzeAmd64UnwindCodeSlots(
    new MockFile(
      fixture.bytes.subarray(fixture.primaryUnwindRva,
        fixture.primaryUnwindRva + Uint32Array.BYTES_PER_ELEMENT + Uint16Array.BYTES_PER_ELEMENT),
      "unwind-at-eof.bin"
    ),
    0, 1, AMD64_UNWIND_INFO_VERSION_1
  );
  assert.strictEqual(analysis.isTruncated, false);
});
