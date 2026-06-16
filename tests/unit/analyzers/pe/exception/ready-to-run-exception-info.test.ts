"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExceptionDirectory } from "../../../../../analyzers/pe/exception/index.js";
import {
  IMAGE_FILE_MACHINE_I386,
  R2R_EXCEPTION_CLAUSE_SIZE,
  R2R_EXCEPTION_LOOKUP_ENTRY_SIZE,
  R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
  createReadyToRun,
  createReadyToRunX86Fixture,
  parseReadyToRunX86Fixture,
  writeExceptionClause,
  writeExceptionLookup
} from "../../../../helpers/pe-ready-to-run-x86-fixture.js";
import { MockFile } from "../../../../helpers/mock-file.js";

class ShortClauseReadMockFile extends MockFile {
  readonly #shortReadOffset: number;

  constructor(bytes: Uint8Array, shortReadOffset: number) {
    super(bytes, "r2r-x86-short-clause.bin");
    this.#shortReadOffset = shortReadOffset;
  }

  override async read(offset: number, length: number): Promise<DataView> {
    const view = await super.read(offset, length);
    if (offset === this.#shortReadOffset && length > R2R_EXCEPTION_CLAUSE_SIZE) {
      return new DataView(view.buffer, view.byteOffset, R2R_EXCEPTION_CLAUSE_SIZE);
    }
    return view;
  }
}

void test("parseExceptionDirectory decodes ReadyToRun ExceptionInfo clauses", async () => {
  const fixture = createReadyToRunX86Fixture();

  const parsed = await parseReadyToRunX86Fixture(fixture);

  assert.ok(parsed);
  assert.equal(parsed.exceptionInfoMethodCount, 1);
  assert.equal(parsed.exceptionClauseCount, 2);
  assert.equal(parsed.catchClauseCount, 1);
  assert.equal(parsed.finallyClauseCount, 1);
  assert.deepEqual(parsed.handlerRvas, [fixture.catchHandlerRva, fixture.finallyHandlerRva]);
});

void test("parseExceptionDirectory reports malformed ReadyToRun ExceptionInfo clauses", async () => {
  const fixture = createReadyToRunX86Fixture();
  // CoreCLR corhdr.h: filter and finally are mutually exclusive CorExceptionFlag kinds.
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/corhdr.h
  writeExceptionClause(
    fixture.view,
    fixture.clauseArrayRva,
    0x0001 | 0x0002,
    fixture.catchHandlerRva - fixture.methodStartRva
  );

  const parsed = await parseReadyToRunX86Fixture(fixture);

  assert.ok(parsed);
  assert.ok(parsed.issues.some(issue => issue.includes("mutually exclusive")));
});

void test("parseExceptionDirectory classifies ReadyToRun ExceptionInfo filter and fault clauses", async () => {
  const fixture = createReadyToRunX86Fixture();
  // CoreCLR corhdr.h: filter and fault are CorExceptionFlag handler kinds.
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/corhdr.h
  writeExceptionClause(
    fixture.view,
    fixture.clauseArrayRva,
    0x0001,
    fixture.catchHandlerRva - fixture.methodStartRva
  );
  writeExceptionClause(
    fixture.view,
    fixture.clauseArrayRva + R2R_EXCEPTION_CLAUSE_SIZE,
    0x0004,
    fixture.finallyHandlerRva - fixture.methodStartRva
  );

  const parsed = await parseReadyToRunX86Fixture(fixture);

  assert.ok(parsed);
  assert.equal(parsed.filterClauseCount, 1);
  assert.equal(parsed.faultClauseCount, 1);
});

void test("parseExceptionDirectory reports malformed ReadyToRun ExceptionInfo extents", async () => {
  const fixture = createReadyToRunX86Fixture();
  writeExceptionLookup(
    fixture.view,
    fixture.exceptionInfoRva + R2R_EXCEPTION_LOOKUP_ENTRY_SIZE,
    0xffff_ffff,
    fixture.clauseArrayRva + R2R_EXCEPTION_CLAUSE_SIZE * 2 - Uint8Array.BYTES_PER_ELEMENT
  );

  const parsed = await parseReadyToRunX86Fixture(fixture);

  assert.ok(parsed);
  assert.ok(parsed.issues.some(issue => issue.includes("clause array size")));
});

void test("parseExceptionDirectory reports malformed ReadyToRun ExceptionInfo table sizes", async () => {
  const fixture = createReadyToRunX86Fixture();

  const parsed = await parseReadyToRunX86Fixture(
    fixture,
    createReadyToRun(
      fixture.runtimeFunctionRva,
      R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE * 2,
      fixture.exceptionInfoRva,
      R2R_EXCEPTION_LOOKUP_ENTRY_SIZE * 2 + Uint8Array.BYTES_PER_ELEMENT
    )
  );

  assert.ok(parsed);
  assert.ok(parsed.issues.some(issue => issue.includes("lookup entry size")));
});

void test("parseExceptionDirectory reports unmapped ReadyToRun ExceptionInfo clause arrays", async () => {
  const fixture = createReadyToRunX86Fixture();

  const parsed = await parseReadyToRunX86Fixture(
    fixture,
    fixture.readyToRun,
    rva => rva === fixture.clauseArrayRva ? null : rva
  );

  assert.ok(parsed);
  assert.ok(parsed.issues.some(issue => issue.includes("does not map to file data")));
});

void test("parseExceptionDirectory reports truncated ReadyToRun ExceptionInfo clause arrays", async () => {
  const fixture = createReadyToRunX86Fixture();

  const parsed = await parseExceptionDirectory(
    new ShortClauseReadMockFile(fixture.bytes, fixture.clauseArrayRva),
    [{
      name: "EXCEPTION",
      rva: fixture.runtimeFunctionRva,
      size: R2R_X86_RUNTIME_FUNCTION_ENTRY_SIZE * 2
    }],
    rva => rva,
    IMAGE_FILE_MACHINE_I386,
    fixture.readyToRun
  );

  assert.ok(parsed);
  assert.ok(parsed.issues.some(issue => issue.includes("clause array is truncated")));
});
