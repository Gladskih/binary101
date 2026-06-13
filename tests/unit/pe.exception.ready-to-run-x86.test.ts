"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import {
  IMAGE_FILE_MACHINE_I386,
  R2R_EXCEPTION_LOOKUP_ENTRY_SIZE,
  R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
  createReadyToRun,
  createReadyToRunX86Fixture,
  parseReadyToRunX86Fixture,
  writeRuntimeFunction
} from "../helpers/pe-ready-to-run-x86-fixture.js";
import { MockFile } from "../helpers/mock-file.js";

void test("parseExceptionDirectory decodes ReadyToRun x86 RuntimeFunctions", async () => {
  const fixture = createReadyToRunX86Fixture();

  const parsed = await parseReadyToRunX86Fixture(fixture);

  assert.ok(parsed);
  assert.equal(parsed.format, "ready-to-run-x86");
  assert.equal(parsed.functionCount, 2);
  assert.deepEqual(parsed.beginRvas, [fixture.methodStartRva, fixture.secondaryMethodStartRva]);
  assert.equal(parsed.uniqueUnwindInfoCount, 2);
  assert.deepEqual(parsed.issues, []);
});

void test("parseExceptionDirectory reports malformed ReadyToRun x86 RuntimeFunctions", async () => {
  const fixture = createReadyToRunX86Fixture();
  writeRuntimeFunction(
    fixture.view,
    fixture.runtimeFunctionRva,
    fixture.methodStartRva,
    fixture.bytes.length
  );

  const parsed = await parseReadyToRunX86Fixture(fixture);

  assert.ok(parsed);
  assert.equal(parsed.invalidEntryCount, 1);
  assert.ok(parsed.issues.some(issue => issue.includes("UnwindData")));
  assert.ok(parsed.issues.some(issue => issue.includes("not present in RuntimeFunctions")));
});

void test("parseExceptionDirectory reports unmapped ReadyToRun x86 begin addresses", async () => {
  const fixture = createReadyToRunX86Fixture();
  writeRuntimeFunction(
    fixture.view,
    fixture.runtimeFunctionRva,
    fixture.bytes.length,
    fixture.methodStartRva
  );

  const parsed = await parseReadyToRunX86Fixture(fixture);

  assert.ok(parsed);
  assert.equal(parsed.invalidEntryCount, 1);
  assert.ok(parsed.issues.some(issue => issue.includes("BeginAddress")));
});

void test("parseExceptionDirectory reports unsorted ReadyToRun x86 RuntimeFunctions", async () => {
  const fixture = createReadyToRunX86Fixture();
  writeRuntimeFunction(
    fixture.view,
    fixture.runtimeFunctionRva,
    fixture.secondaryMethodStartRva,
    fixture.methodStartRva
  );
  writeRuntimeFunction(
    fixture.view,
    fixture.runtimeFunctionRva + R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
    fixture.methodStartRva,
    fixture.secondaryMethodStartRva
  );

  const parsed = await parseReadyToRunX86Fixture(fixture);

  assert.ok(parsed);
  assert.ok(parsed.issues.some(issue => issue.includes("not sorted by BeginAddress")));
});

void test("parseExceptionDirectory reports malformed ReadyToRun x86 directory sizes", async () => {
  const fixture = createReadyToRunX86Fixture();
  const nonMultiple = await parseReadyToRunX86Fixture(
    fixture,
    createReadyToRun(
      fixture.runtimeFunctionRva,
      R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE * 2 + Uint8Array.BYTES_PER_ELEMENT,
      fixture.exceptionInfoRva,
      R2R_EXCEPTION_LOOKUP_ENTRY_SIZE * 2
    )
  );
  const tooSmall = await parseReadyToRunX86Fixture(
    fixture,
    createReadyToRun(
      fixture.runtimeFunctionRva,
      R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE - Uint8Array.BYTES_PER_ELEMENT,
      fixture.exceptionInfoRva,
      R2R_EXCEPTION_LOOKUP_ENTRY_SIZE * 2
    )
  );

  assert.ok(nonMultiple);
  assert.ok(nonMultiple.issues.some(issue => issue.includes("multiple")));
  assert.ok(tooSmall);
  assert.equal(tooSmall.functionCount, 0);
  assert.ok(tooSmall.issues.some(issue => issue.includes("smaller than one")));
});

void test("parseExceptionDirectory keeps ordinary x86 exception directories unsupported", async () => {
  const runtimeFunctionRva = Uint32Array.BYTES_PER_ELEMENT;
  const bytes = new Uint8Array(runtimeFunctionRva + R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE).fill(0);
  const view = new DataView(bytes.buffer);
  writeRuntimeFunction(view, runtimeFunctionRva, 0, 0);

  const parsed = await parseExceptionDirectory(
    new MockFile(bytes, "ordinary-x86.bin"),
    [{ name: "EXCEPTION", rva: runtimeFunctionRva, size: R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE }],
    rva => rva,
    IMAGE_FILE_MACHINE_I386
  );

  assert.ok(parsed);
  assert.equal(parsed.format, undefined);
  assert.ok(parsed.issues.some(issue => issue.includes("not implemented")));
});
