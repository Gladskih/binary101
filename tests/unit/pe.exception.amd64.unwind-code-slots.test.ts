"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  analyzeAmd64UnwindCodeSlots
} from "../../analyzers/pe/exception/amd64/unwind-code-slots.js";
import { MockFile } from "../helpers/mock-file.js";
import {
  AMD64_UNWIND_INFO_VERSION_1,
  AMD64_UNWIND_INFO_VERSION_2,
  createAmd64ExceptionFixtureWithSlots,
  createTruncatedUnwindCodeArrayFixture,
  epilogPaddingSlot,
  epilogScopeSlot,
  regularUnwindSlot
} from "../helpers/pe-amd64-unwind-fixture.js";

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
