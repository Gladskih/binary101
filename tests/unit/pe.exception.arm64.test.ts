"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExceptionDirectory } from "../../analyzers/pe/exception.js";
import { MockFile } from "../helpers/mock-file.js";

// Microsoft PE format, "Machine Types":
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
const IMAGE_FILE_MACHINE_ARM64 = 0xaa64;
// Microsoft ARM64 exception-handling docs, ".pdata records":
// https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling
const ARM64_RUNTIME_FUNCTION_ENTRY_SIZE = 8;
const ARM64_XDATA_HEADER_HAS_EXCEPTION_HANDLER = 1 << 20;
const ARM64_XDATA_HEADER_SINGLE_EPILOG = 1 << 21;
const ARM64_XDATA_HEADER_ONE_UNWIND_WORD = 1 << 27;

const writeArm64RuntimeFunction = (
  view: DataView,
  offset: number,
  begin: number,
  unwindDataWord: number
): void => {
  view.setUint32(offset, begin, true);
  view.setUint32(offset + Uint32Array.BYTES_PER_ELEMENT, unwindDataWord, true);
};

const parseArm64ExceptionFixture = (
  bytes: Uint8Array,
  fileName: string,
  directoryRva: number,
  directorySize: number
) => parseExceptionDirectory(
  new MockFile(bytes, fileName),
  [{ name: "EXCEPTION", rva: directoryRva, size: directorySize }],
  value => value,
  IMAGE_FILE_MACHINE_ARM64
);

void test("parseExceptionDirectory parses ARM64 pdata entries that point to xdata records with handlers", async () => {
  const bytes = new Uint8Array(0x400).fill(0);
  const exOff = 0x80;
  const xdataRva = 0x200;
  const handlerRva = 0x300;
  const dv = new DataView(bytes.buffer);

  // Microsoft ARM64 exception-handling docs:
  // each ARM64 .pdata record is 8 bytes, with the second word holding either packed
  // unwind data or an Exception Information RVA when Flag == 0.
  // https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling
  writeArm64RuntimeFunction(dv, exOff, 0x100, xdataRva);
  dv.setUint32(
    xdataRva,
    1 |
      ARM64_XDATA_HEADER_HAS_EXCEPTION_HANDLER |
      ARM64_XDATA_HEADER_SINGLE_EPILOG |
      ARM64_XDATA_HEADER_ONE_UNWIND_WORD,
    true
  );
  dv.setUint32(xdataRva + Uint32Array.BYTES_PER_ELEMENT * 2, handlerRva, true);

  const parsed = await parseArm64ExceptionFixture(
    bytes,
    "exception-arm64-xdata.bin",
    exOff,
    ARM64_RUNTIME_FUNCTION_ENTRY_SIZE
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 1);
  assert.deepEqual(parsed.beginRvas, [0x100]);
  assert.strictEqual(parsed.uniqueUnwindInfoCount, 1);
  assert.strictEqual(parsed.handlerUnwindInfoCount, 1);
  assert.deepEqual(parsed.handlerRvas, [handlerRva]);
  assert.strictEqual(parsed.invalidEntryCount, 0);
  assert.deepEqual(parsed.issues, []);
});

void test("parseExceptionDirectory accepts ARM64 packed unwind pdata entries", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const exOff = 0x80;
  const dv = new DataView(bytes.buffer);
  const packedFlagSinglePrologAndEpilog = 0x1;
  const packedFunctionLengthOneInstruction = 1 << 2;

  // Microsoft ARM64 exception-handling docs:
  // if the Flag field is non-zero, the second word contains packed unwind data
  // instead of an xdata RVA.
  // https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling
  writeArm64RuntimeFunction(
    dv,
    exOff,
    0x100,
    packedFlagSinglePrologAndEpilog | packedFunctionLengthOneInstruction
  );

  const parsed = await parseArm64ExceptionFixture(
    bytes,
    "exception-arm64-packed.bin",
    exOff,
    ARM64_RUNTIME_FUNCTION_ENTRY_SIZE
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 1);
  assert.deepEqual(parsed.beginRvas, [0x100]);
  assert.strictEqual(parsed.uniqueUnwindInfoCount, 1);
  assert.strictEqual(parsed.handlerUnwindInfoCount, 0);
  assert.strictEqual(parsed.invalidEntryCount, 0);
  assert.deepEqual(parsed.issues, []);
});
