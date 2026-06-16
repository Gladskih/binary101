"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { FileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { parseExceptionDirectory } from "../../../../../analyzers/pe/exception/index.js";
import {
  IMAGE_FILE_MACHINE_I386,
  NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
  type NativeAotX86Fixture,
  createNativeAotX86Fixture,
  parseNativeAotX86Fixture,
  writeNativeAotX86RuntimeFunction,
  writeNativeAotX86UnwindInfo
} from "../../../../helpers/pe-native-aot-x86-fixture.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const createReaderWithShortUnwindRead = (fixture: NativeAotX86Fixture): FileRangeReader => {
  const reader: FileRangeReader = {
    size: fixture.bytes.length,
    read: async (offset, size) => {
      if (offset === fixture.unwindRvas[0]) return new DataView(new ArrayBuffer(0));
      return new DataView(
        fixture.bytes.buffer,
        offset,
        Math.max(0, Math.min(size, fixture.bytes.length - offset))
      );
    },
    readBytes: async (offset, size) => {
      const view = await reader.read(offset, size);
      return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    }
  };
  return reader;
};

void test("parseExceptionDirectory decodes NativeAOT x86 RuntimeFunctions", async () => {
  const fixture = createNativeAotX86Fixture();

  const parsed = await parseNativeAotX86Fixture(fixture);

  assert.ok(parsed);
  assert.equal(parsed.format, "native-aot-x86");
  assert.equal(parsed.functionCount, fixture.beginRvas.length);
  assert.deepEqual(parsed.beginRvas, fixture.beginRvas);
  assert.equal(parsed.uniqueUnwindInfoCount, fixture.unwindRvas.length);
  assert.deepEqual(parsed.issues, []);
});

void test("parseExceptionDirectory does not treat ordinary x86 pdata as NativeAOT", async () => {
  const fixture = createNativeAotX86Fixture([Uint32Array.BYTES_PER_ELEMENT]);

  const parsed = await parseExceptionDirectory(
    new MockFile(fixture.bytes, "ordinary-x86-pdata.bin"),
    [{
      name: "EXCEPTION",
      rva: fixture.directoryRva,
      size: NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE
    }],
    rva => rva,
    IMAGE_FILE_MACHINE_I386
  );

  assert.ok(parsed);
  assert.equal(parsed.format, undefined);
  assert.ok(parsed.issues.some(issue => issue.includes("not implemented")));
});

void test("parseExceptionDirectory reports malformed NativeAOT x86 locations", async () => {
  const fixture = createNativeAotX86Fixture();
  const zeroRva = await parseExceptionDirectory(
    new MockFile(fixture.bytes, "native-aot-x86-zero-rva.bin"),
    [{
      name: "EXCEPTION",
      rva: 0,
      size: NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE
    }],
    rva => rva,
    IMAGE_FILE_MACHINE_I386,
    undefined,
    fixture.nativeAotCandidate
  );
  const outsideFile = await parseNativeAotX86Fixture(
    fixture,
    NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
    () => fixture.bytes.length
  );
  const unmappedDirectory = await parseNativeAotX86Fixture(
    fixture,
    NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
    () => null
  );

  assert.ok(zeroRva);
  assert.ok(zeroRva.issues.some(issue => issue.includes("RVA is 0")));
  assert.ok(outsideFile);
  assert.ok(outsideFile.issues.some(issue => issue.includes("outside the file")));
  assert.ok(unmappedDirectory);
  assert.ok(unmappedDirectory.issues.some(issue => issue.includes("could not be mapped")));
});

void test("parseExceptionDirectory reports incomplete NativeAOT x86 directories", async () => {
  const fixture = createNativeAotX86Fixture();
  const parsed = await parseNativeAotX86Fixture(
    fixture,
    NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
    () => fixture.bytes.length - Uint8Array.BYTES_PER_ELEMENT
  );

  assert.ok(parsed);
  assert.equal(parsed.functionCount, 0);
  assert.ok(parsed.issues.some(issue => issue.includes("truncated")));
  assert.ok(parsed.issues.some(issue => issue.includes("complete")));
});

void test("parseExceptionDirectory reports short NativeAOT x86 unwind reads", async () => {
  const fixture = createNativeAotX86Fixture();

  const parsed = await parseExceptionDirectory(
    createReaderWithShortUnwindRead(fixture),
    [{
      name: "EXCEPTION",
      rva: fixture.directoryRva,
      size: NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE
    }],
    rva => rva,
    IMAGE_FILE_MACHINE_I386,
    undefined,
    fixture.nativeAotCandidate
  );

  assert.ok(parsed);
  assert.equal(parsed.invalidEntryCount, 1);
  assert.ok(parsed.issues.some(issue => issue.includes("UnwindData")));
  assert.ok(parsed.issues.some(issue => issue.includes("truncated")));
});

void test("parseExceptionDirectory reports malformed NativeAOT x86 directory sizes", async () => {
  const fixture = createNativeAotX86Fixture();
  const nonMultiple = await parseNativeAotX86Fixture(
    fixture,
    NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE * 2 + Uint8Array.BYTES_PER_ELEMENT
  );
  const tooSmall = await parseNativeAotX86Fixture(
    fixture,
    NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE - Uint8Array.BYTES_PER_ELEMENT
  );

  assert.ok(nonMultiple);
  assert.ok(nonMultiple.issues.some(issue => issue.includes("multiple")));
  assert.ok(tooSmall);
  assert.equal(tooSmall.functionCount, 0);
  assert.ok(tooSmall.issues.some(issue => issue.includes("smaller than one")));
});

void test("parseExceptionDirectory reports invalid NativeAOT x86 runtime ranges", async () => {
  const fixture = createNativeAotX86Fixture();
  writeNativeAotX86RuntimeFunction(
    fixture.view,
    fixture.directoryRva,
    fixture.endRvas[0]!,
    fixture.beginRvas[0]!,
    fixture.unwindRvas[0]!
  );

  const parsed = await parseNativeAotX86Fixture(fixture);

  assert.ok(parsed);
  assert.equal(parsed.invalidEntryCount, 1);
  assert.ok(parsed.issues.some(issue => issue.includes("BeginAddress")));
});

void test("parseExceptionDirectory reports NativeAOT x86 runtime RVAs outside file", async () => {
  const fixture = createNativeAotX86Fixture();

  const parsed = await parseNativeAotX86Fixture(
    fixture,
    NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
    rva => rva === fixture.beginRvas[0] ? fixture.bytes.length : rva
  );

  assert.ok(parsed);
  assert.equal(parsed.invalidEntryCount, 1);
  assert.ok(parsed.issues.some(issue => issue.includes("maps outside the file")));
});

void test("parseExceptionDirectory reports invalid NativeAOT x86 unwind RVAs", async () => {
  const fixture = createNativeAotX86Fixture();
  writeNativeAotX86RuntimeFunction(
    fixture.view,
    fixture.directoryRva,
    fixture.beginRvas[0]!,
    fixture.endRvas[0]!,
    fixture.bytes.length
  );

  const parsed = await parseNativeAotX86Fixture(fixture);

  assert.ok(parsed);
  assert.equal(parsed.invalidEntryCount, 1);
  assert.ok(parsed.issues.some(issue => issue.includes("UnwindData")));
});

void test("parseExceptionDirectory reports truncated NativeAOT x86 unwind blocks", async () => {
  const fixture = createNativeAotX86Fixture();
  writeNativeAotX86RuntimeFunction(
    fixture.view,
    fixture.directoryRva,
    fixture.beginRvas[0]!,
    fixture.endRvas[0]!,
    fixture.bytes.length - Uint8Array.BYTES_PER_ELEMENT
  );

  const parsed = await parseNativeAotX86Fixture(fixture);

  assert.ok(parsed);
  assert.equal(parsed.invalidEntryCount, 1);
  assert.ok(parsed.issues.some(issue => issue.includes("UnwindData")));
  assert.ok(parsed.issues.some(issue => issue.includes("truncated")));
});

void test("parseExceptionDirectory reports NativeAOT x86 FunctionLength mismatches", async () => {
  const fixture = createNativeAotX86Fixture();
  writeNativeAotX86UnwindInfo(
    fixture.view,
    fixture.unwindRvas[0]!,
    fixture.endRvas[0]! - fixture.beginRvas[0]! + Uint8Array.BYTES_PER_ELEMENT
  );

  const parsed = await parseNativeAotX86Fixture(fixture);

  assert.ok(parsed);
  assert.equal(parsed.invalidEntryCount, 1);
  assert.ok(parsed.issues.some(issue => issue.includes("FunctionLength")));
});

void test("parseExceptionDirectory reports unsorted NativeAOT x86 RuntimeFunctions", async () => {
  const fixture = createNativeAotX86Fixture();
  writeNativeAotX86RuntimeFunction(
    fixture.view,
    fixture.directoryRva,
    fixture.beginRvas[1]!,
    fixture.endRvas[1]!,
    fixture.unwindRvas[1]!
  );
  writeNativeAotX86RuntimeFunction(
    fixture.view,
    fixture.directoryRva + NATIVE_AOT_X86_RUNTIME_FUNCTION_ENTRY_SIZE,
    fixture.beginRvas[0]!,
    fixture.endRvas[0]!,
    fixture.unwindRvas[0]!
  );

  const parsed = await parseNativeAotX86Fixture(fixture);

  assert.ok(parsed);
  assert.ok(parsed.issues.some(issue => issue.includes("not sorted by BeginAddress")));
});
