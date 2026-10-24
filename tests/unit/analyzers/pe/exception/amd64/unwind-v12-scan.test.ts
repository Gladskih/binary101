import assert from "node:assert/strict";
import { test } from "node:test";
import { scanAmd64UnwindInfos } from "../../../../../../analyzers/pe/exception/amd64/unwind-info.js";
import { createAmd64ExceptionFixtureWithSlots } from "../../../../../helpers/pe-amd64-unwind-fixture.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import { createPeWithV12ExceptionCopy } from "../../../../../fixtures/pe-debug-file.js";
import { parsePeHeaders } from "../../../../../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../../../../../analyzers/pe/debug/directory.js";

// Microsoft x64 EH, UWOP encodings: the short offsets scale by 8/16;
// FAR operands and ALLOC_LARGE OpInfo=1 are unscaled little-endian DWORDs.
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
void test("v1 scan summarizes semantic operands once per unique unwind block", async () => {
  const fixture = createAmd64ExceptionFixtureWithSlots([
    [25, 0x1a], [24, 0x79], [0, 0], [1, 0], [23, 0x68], [3, 0],
    [22, 0x65], [8, 0], [1, 0], [21, 0x74], [5, 0], [20, 3],
    [19, 0x11], [0, 0x10], [1, 0], [18, 1], [32, 0], [17, 0x32], [16, 0x50]
  ], { version: 1 });
  fixture.bytes[fixture.primaryUnwindRva + 1] = 32;
  fixture.bytes[fixture.primaryUnwindRva + 3] = 0x25; // RBP = RSP + 32.
  const issues: string[] = [];
  const parsed = await scanAmd64UnwindInfos(new MockFile(fixture.bytes), rva => rva,
    new Set([fixture.primaryUnwindRva]), issues);

  assert.deepEqual(parsed.version12?.allocationCounts, { 32: 1, 256: 1, 69632: 1 });
  assert.deepEqual(parsed.version12?.registerCounts, { RBP: 1, RDI: 1, RSI: 1, XMM6: 1, XMM7: 1 });
  assert.deepEqual(parsed.version12?.frameRegisterCounts, { RBP: 1 });
  assert.deepEqual(parsed.version12?.saveOffsetCounts, { 40: 1, 48: 1, 65536: 1, 65544: 1 });
  assert.deepEqual(parsed.version12?.machineFrameCounts, { 48: 1 });
  assert.equal(parsed.version12?.operationCounts["SET_FPREG"], 1);
  assert.equal(parsed.version12?.blockCount, 1);
  assert.deepEqual(issues, []);
});

void test("raw debug copies summarize shared v2 blocks once without treating epilogs as operations", async () => {
  const file = createPeWithV12ExceptionCopy();
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const parsed = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const exception = parsed.entries[0]?.exception;

  assert.equal(exception?.functionCount, 2);
  assert.equal(exception?.unwindInfoV12?.blockCount, 1);
  assert.equal(exception?.epilogScopeCount, 1);
  assert.deepEqual(exception?.unwindInfoV12?.operationCounts,
    { SAVE_XMM128: 1, SET_FPREG: 1, ALLOC_SMALL: 1, PUSH_NONVOL: 1 });
  assert.deepEqual(exception?.issues, []);
});

void test("malformed operations retain only a decoded prefix and remain visibly incomplete", async () => {
  const fixture = createAmd64ExceptionFixtureWithSlots([[3, 0x02], [2, 0x0b], [1, 0x50]], { version: 1 });
  const issues: string[] = [];
  const parsed = await scanAmd64UnwindInfos(new MockFile(fixture.bytes), rva => rva,
    new Set([fixture.primaryUnwindRva]), issues);

  assert.deepEqual(parsed.version12?.allocationCounts, { 8: 1 });
  assert.deepEqual(parsed.version12?.registerCounts, {});
  assert.equal(parsed.version12?.incompleteBlockCount, 1);
  assert.match(issues[0]!, /opcode 11 is unknown or reserved/);
});
