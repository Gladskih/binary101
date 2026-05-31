"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readAmd64RuntimeFunctions } from "../../analyzers/pe/exception/amd64/runtime-functions.js";
import { MockFile } from "../helpers/mock-file.js";
import {
  AMD64_UNWIND_INFO_VERSION_1,
  RUNTIME_FUNCTION_ENTRY_SIZE_BYTES,
  UNWIND_INFO_HEADER_SIZE_BYTES,
  createRvaAllocator,
  writeRuntimeFunction
} from "../helpers/pe-amd64-unwind-fixture.js";

const identityRvaToOffset = (rva: number): number => rva;

const createRuntimeFunctionFixture = (entryCount: number): {
  beginRvas: number[];
  bytes: Uint8Array;
  directoryRva: number;
  functionSizeBytes: number;
  unwindInfoRva: number;
  view: DataView;
} => {
  const allocator = createRvaAllocator();
  const directoryRva = allocator.allocate(entryCount * RUNTIME_FUNCTION_ENTRY_SIZE_BYTES);
  const functionSizeBytes = Uint8Array.BYTES_PER_ELEMENT;
  const beginRvas = Array.from({ length: entryCount }, () => allocator.allocate(functionSizeBytes));
  const unwindInfoRva = allocator.allocate(UNWIND_INFO_HEADER_SIZE_BYTES);
  const bytes = new Uint8Array(allocator.current()).fill(0);
  const view = new DataView(bytes.buffer);
  for (const [index, beginRva] of beginRvas.entries()) {
    writeRuntimeFunction(
      view,
      directoryRva + index * RUNTIME_FUNCTION_ENTRY_SIZE_BYTES,
      beginRva,
      beginRva + functionSizeBytes,
      unwindInfoRva
    );
  }
  bytes[unwindInfoRva] = AMD64_UNWIND_INFO_VERSION_1;
  return { beginRvas, bytes, directoryRva, functionSizeBytes, unwindInfoRva, view };
};

void test("readAmd64RuntimeFunctions reads valid entries and unique unwind RVAs", async () => {
  const fixture = createRuntimeFunctionFixture(2);
  const issues: string[] = [];
  const table = await readAmd64RuntimeFunctions(
    new MockFile(fixture.bytes, "amd64-runtime-functions.bin"),
    fixture.directoryRva,
    2,
    identityRvaToOffset,
    issues
  );
  assert.strictEqual(table.functionCount, 2);
  assert.strictEqual(table.invalidEntryCount, 0);
  assert.deepEqual(table.beginRvas, fixture.beginRvas);
  assert.deepEqual([...table.unwindRvas], [fixture.unwindInfoRva]);
  assert.deepEqual(issues, []);
});

void test("readAmd64RuntimeFunctions reports unsorted valid entries once", async () => {
  const fixture = createRuntimeFunctionFixture(2);
  const earlierFunctionRva = fixture.beginRvas[0]!;
  const laterFunctionRva = fixture.beginRvas[1]!;
  writeRuntimeFunction(
    fixture.view,
    fixture.directoryRva,
    laterFunctionRva,
    laterFunctionRva + fixture.functionSizeBytes,
    fixture.unwindInfoRva
  );
  writeRuntimeFunction(
    fixture.view,
    fixture.directoryRva + RUNTIME_FUNCTION_ENTRY_SIZE_BYTES,
    earlierFunctionRva,
    earlierFunctionRva + fixture.functionSizeBytes,
    fixture.unwindInfoRva
  );
  const issues: string[] = [];
  const table = await readAmd64RuntimeFunctions(
    new MockFile(fixture.bytes, "amd64-runtime-functions-unsorted.bin"),
    fixture.directoryRva,
    2,
    identityRvaToOffset,
    issues
  );
  assert.deepEqual(table.beginRvas, [laterFunctionRva, earlierFunctionRva]);
  assert.strictEqual(issues.filter(issue => /not sorted/i.test(issue)).length, 1);
});

void test("readAmd64RuntimeFunctions skips invalid begin ranges and ignores their unwind seeds", async () => {
  const fixture = createRuntimeFunctionFixture(2);
  const validFunctionRva = fixture.beginRvas[0]!;
  const invalidFunctionRva = fixture.beginRvas[1]!;
  const invalidUnwindInfoRva = fixture.unwindInfoRva + UNWIND_INFO_HEADER_SIZE_BYTES;
  writeRuntimeFunction(
    fixture.view,
    fixture.directoryRva + RUNTIME_FUNCTION_ENTRY_SIZE_BYTES,
    invalidFunctionRva,
    invalidFunctionRva,
    invalidUnwindInfoRva
  );
  const issues: string[] = [];
  const table = await readAmd64RuntimeFunctions(
    new MockFile(fixture.bytes, "amd64-runtime-functions-invalid.bin"),
    fixture.directoryRva,
    2,
    identityRvaToOffset,
    issues
  );
  assert.strictEqual(table.functionCount, 2);
  assert.strictEqual(table.invalidEntryCount, 1);
  assert.deepEqual(table.beginRvas, [validFunctionRva]);
  assert.deepEqual([...table.unwindRvas], [fixture.unwindInfoRva]);
  assert.ok(issues.some(issue => /RUNTIME_FUNCTION.*BeginAddress/i.test(issue)));
});

void test("readAmd64RuntimeFunctions rejects unwind pointers back into the exception table", async () => {
  const fixture = createRuntimeFunctionFixture(1);
  writeRuntimeFunction(
    fixture.view,
    fixture.directoryRva,
    fixture.beginRvas[0]!,
    fixture.beginRvas[0]! + fixture.functionSizeBytes,
    fixture.directoryRva
  );
  const issues: string[] = [];
  const table = await readAmd64RuntimeFunctions(
    new MockFile(fixture.bytes, "amd64-runtime-functions-pdata-unwind.bin"),
    fixture.directoryRva,
    1,
    identityRvaToOffset,
    issues
  );

  assert.strictEqual(table.invalidEntryCount, 1);
  assert.deepEqual([...table.unwindRvas], []);
  assert.ok(issues.some(issue => /RUNTIME_FUNCTION.*UnwindData/i.test(issue)));
});

void test("readAmd64RuntimeFunctions resolves indirect unwind data entries", async () => {
  const fixture = createRuntimeFunctionFixture(2);
  const indirectFunctionRva = fixture.beginRvas[1]!;
  writeRuntimeFunction(
    fixture.view,
    fixture.directoryRva + RUNTIME_FUNCTION_ENTRY_SIZE_BYTES,
    indirectFunctionRva,
    indirectFunctionRva + fixture.functionSizeBytes,
    fixture.directoryRva | 1
  );
  const issues: string[] = [];
  const table = await readAmd64RuntimeFunctions(
    new MockFile(fixture.bytes, "amd64-runtime-functions-indirect.bin"),
    fixture.directoryRva,
    2,
    identityRvaToOffset,
    issues
  );

  assert.strictEqual(table.invalidEntryCount, 0);
  assert.deepEqual([...table.unwindRvas], [fixture.unwindInfoRva]);
  assert.deepEqual(issues, []);
});

void test("readAmd64RuntimeFunctions rejects missing top-level unwind addresses", async () => {
  const fixture = createRuntimeFunctionFixture(1);
  writeRuntimeFunction(
    fixture.view,
    fixture.directoryRva,
    fixture.beginRvas[0]!,
    fixture.beginRvas[0]! + fixture.functionSizeBytes,
    0
  );
  const issues: string[] = [];
  const table = await readAmd64RuntimeFunctions(
    new MockFile(fixture.bytes, "amd64-runtime-functions-zero-unwind.bin"),
    fixture.directoryRva,
    1,
    identityRvaToOffset,
    issues
  );

  assert.strictEqual(table.invalidEntryCount, 1);
  assert.deepEqual([...table.unwindRvas], []);
  assert.ok(issues.some(issue => /RUNTIME_FUNCTION.*UnwindData.*zero/i.test(issue)));
});

void test("readAmd64RuntimeFunctions stops when declared entries stop mapping", async () => {
  const allocator = createRvaAllocator();
  const directoryRva = allocator.allocate(RUNTIME_FUNCTION_ENTRY_SIZE_BYTES * 2);
  const functionRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const unwindInfoRva = allocator.allocate(UNWIND_INFO_HEADER_SIZE_BYTES);
  const bytes = new Uint8Array(allocator.current()).fill(0);
  bytes[unwindInfoRva] = AMD64_UNWIND_INFO_VERSION_1;
  writeRuntimeFunction(
    new DataView(bytes.buffer),
    directoryRva,
    functionRva,
    functionRva + Uint8Array.BYTES_PER_ELEMENT,
    unwindInfoRva
  );
  const issues: string[] = [];
  const table = await readAmd64RuntimeFunctions(
    new MockFile(bytes, "amd64-runtime-functions-truncated.bin"),
    directoryRva,
    2,
    rva => rva === directoryRva + RUNTIME_FUNCTION_ENTRY_SIZE_BYTES ? null : rva,
    issues
  );
  assert.strictEqual(table.functionCount, 1);
  assert.ok(issues.some(issue => /truncated/i.test(issue)));
});
