"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { scanAmd64UnwindInfos } from "../../../../../../../analyzers/pe/exception/amd64/unwind-info.js";
import { MockFile } from "../../../../../../helpers/mock-file.js";
import {
  UNW_FLAG_EHANDLER,
  createAmd64ExceptionFixtureWithSlots,
  createChainedAmd64ExceptionFixture,
  createRvaAllocator,
  epilogScopeSlot,
  writePrimaryHandlerRva
} from "../../../../../../helpers/pe-amd64-unwind-fixture.js";

const identityRvaToOffset = (rva: number): number => rva;

void test("scanAmd64UnwindInfos records handler tails and v2 epilog stats", async () => {
  const fixture = createAmd64ExceptionFixtureWithSlots(
    [epilogScopeSlot()],
    { flags: UNW_FLAG_EHANDLER, trailingBytes: Uint32Array.BYTES_PER_ELEMENT }
  );
  writePrimaryHandlerRva(fixture, fixture.functionEndRva);
  const issues: string[] = [];
  const table = await scanAmd64UnwindInfos(
    new MockFile(fixture.bytes, "amd64-unwind-info-handler.bin"),
    identityRvaToOffset,
    new Set([fixture.primaryUnwindRva]),
    issues
  );
  assert.deepEqual(table.handlerRvas, [fixture.functionEndRva]);
  assert.strictEqual(table.handlerUnwindInfoCount, 1);
  assert.strictEqual(table.unwindInfoVersion2Count, 1);
  assert.strictEqual(table.epilogUnwindInfoCount, 1);
  assert.strictEqual(table.epilogScopeCount, 1);
  assert.deepEqual(issues, []);
});

void test("scanAmd64UnwindInfos follows chained v2 unwind records", async () => {
  const fixture = createChainedAmd64ExceptionFixture([epilogScopeSlot()]);
  const issues: string[] = [];
  const table = await scanAmd64UnwindInfos(
    new MockFile(fixture.bytes, "amd64-unwind-info-chain.bin"),
    identityRvaToOffset,
    new Set([fixture.primaryUnwindRva]),
    issues
  );
  assert.strictEqual(table.uniqueUnwindInfoCount, 2);
  assert.strictEqual(table.chainedUnwindInfoCount, 1);
  assert.strictEqual(table.unwindInfoVersion2Count, 2);
  assert.strictEqual(table.epilogScopeCount, 1);
  assert.deepEqual(issues, []);
});

void test("scanAmd64UnwindInfos reports unreadable unwind records", async () => {
  const allocator = createRvaAllocator();
  const unmappedUnwindRva = allocator.allocate(Uint32Array.BYTES_PER_ELEMENT);
  const issues: string[] = [];
  const table = await scanAmd64UnwindInfos(
    new MockFile(new Uint8Array(0), "amd64-unwind-info-unreadable.bin"),
    () => null,
    new Set([unmappedUnwindRva]),
    issues
  );
  assert.strictEqual(table.uniqueUnwindInfoCount, 1);
  assert.strictEqual(table.unwindInfoVersion1Count, 0);
  assert.strictEqual(table.unwindInfoVersion2Count, 0);
  assert.ok(issues.some(issue => /could not be read/i.test(issue)));
});
