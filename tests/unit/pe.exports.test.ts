"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExportDirectory } from "../../analyzers/pe/exports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";

const encoder = new TextEncoder();

void test("parseExportDirectory extracts names and forwarders", async () => {
  const bytes = new Uint8Array(1024).fill(0);
  const dv = new DataView(bytes.buffer);
  const baseExp = 128;

  dv.setUint32(baseExp + 0, 1, true);
  dv.setUint32(baseExp + 4, 0x11223344, true);
  dv.setUint16(baseExp + 8, 1, true);
  dv.setUint16(baseExp + 10, 0, true);
  const nameRva = 300;
  dv.setUint32(baseExp + 12, nameRva, true);
  dv.setUint32(baseExp + 16, 1, true);
  dv.setUint32(baseExp + 20, 2, true);
  dv.setUint32(baseExp + 24, 1, true);
  dv.setUint32(baseExp + 28, 400, true);
  dv.setUint32(baseExp + 32, 420, true);
  dv.setUint32(baseExp + 36, 430, true);

  encoder.encodeInto("demo.dll\0", new Uint8Array(bytes.buffer, nameRva));
  dv.setUint32(400 + 0, 0x7000, true);
  const forwarderRva = baseExp + 64;
  dv.setUint32(400 + 4, forwarderRva, true);
  dv.setUint32(420, 440, true);
  dv.setUint16(430, 1, true);
  encoder.encodeInto("FuncB\0", new Uint8Array(bytes.buffer, 440));
  encoder.encodeInto("KERNEL32.Forward\0", new Uint8Array(bytes.buffer, forwarderRva));

  const result = await parseExportDirectory(
    new MockFile(bytes, "exports.bin"),
    [{ name: "EXPORT", rva: baseExp, size: 96 }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.dllName, "demo.dll");
  assert.equal(definedResult.entries.length, 2);
  const secondEntry = expectDefined(definedResult.entries[1]);
  assert.equal(secondEntry.forwarder, "KERNEL32.Forward");
  assert.equal(secondEntry.name, "FuncB");
});

void test("parseExportDirectory stops at available function table size", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const expRva = 0x20;
  dv.setUint32(expRva + 20, 10, true);
  dv.setUint32(expRva + 28, 0x60, true);
  dv.setUint32(0x60, 0x1234, true);

  const result = await parseExportDirectory(
    new MockFile(bytes, "exports-trunc.bin"),
    [{ name: "EXPORT", rva: expRva, size: 40 }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 8);
  const firstEntry = expectDefined(definedResult.entries[0]);
  assert.equal(firstEntry.rva, 0x1234);
  assert.equal(definedResult.entries[7]?.rva, 0);
});

void test("parseExportDirectory truncates entries when EAT is shorter than NumberOfFunctions", async () => {
  const bytes = new Uint8Array(0x48).fill(0);
  const dv = new DataView(bytes.buffer);
  const expRva = 0x10;
  dv.setUint32(expRva + 20, 10, true);
  dv.setUint32(expRva + 28, 0x40, true);
  dv.setUint32(0x40, 0x1111, true);
  dv.setUint32(0x44, 0x2222, true);

  const result = await parseExportDirectory(
    new MockFile(bytes, "exports-eat-trunc.bin"),
    [{ name: "EXPORT", rva: expRva, size: 64 }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 2);
  assert.equal(definedResult.entries[0]?.rva, 0x1111);
  assert.equal(definedResult.entries[1]?.rva, 0x2222);
});

void test("parseExportDirectory ignores names beyond available name/ordinal tables", async () => {
  const bytes = new Uint8Array(0xe0).fill(0);
  const dv = new DataView(bytes.buffer);
  const expRva = 0x20;
  dv.setUint32(expRva + 16, 1, true);
  dv.setUint32(expRva + 20, 2, true);
  dv.setUint32(expRva + 24, 3, true);
  dv.setUint32(expRva + 28, 0x80, true);
  dv.setUint32(expRva + 32, 0xd4, true);
  dv.setUint32(expRva + 36, 0xdc, true);
  dv.setUint32(0x80, 0x1000, true);
  dv.setUint32(0x84, 0x2000, true);
  dv.setUint32(0xd4, 0xc0, true);
  dv.setUint32(0xd8, 0x00, true);
  dv.setUint16(0xdc, 0, true);
  dv.setUint16(0xde, 1, true);
  encoder.encodeInto("OnlyName\0", new Uint8Array(bytes.buffer, 0xc0));

  const result = await parseExportDirectory(
    new MockFile(bytes, "exports-names-trunc.bin"),
    [{ name: "EXPORT", rva: expRva, size: 80 }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 2);
  assert.equal(definedResult.entries[0]?.name, "OnlyName");
  assert.ok(definedResult.entries[1]?.name === null || definedResult.entries[1]?.name === "");
});

void test("parseExportDirectory bounds the initial directory read to the fixed header size", async () => {
  const bytes = new Uint8Array(0x80).fill(0);
  const dv = new DataView(bytes.buffer);
  const expRva = 0x20;
  dv.setUint32(expRva + 16, 1, true);
  dv.setUint32(expRva + 20, 1, true);
  dv.setUint32(expRva + 28, 0x2000, true);

  const tracked = createSliceTrackingFile(bytes, 0x400000, "exports-bounded-read.bin");
  const result = await parseExportDirectory(
    tracked.file,
    [{ name: "EXPORT", rva: expRva, size: 0x200000 }],
    value => (value < bytes.length ? value : null),
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.ok(definedResult.issues.some(issue => /does not map/i.test(issue)));
  assert.ok(
    Math.max(...tracked.requests) <= 40,
    `Expected fixed-size export header read, got requests ${tracked.requests.join(", ")}`
  );
});

void test("parseExportDirectory stops reading export strings at EOF without unbounded retries", async () => {
  const bytes = new Uint8Array(0x41).fill(0);
  const dv = new DataView(bytes.buffer);
  const expRva = 0x10;
  dv.setUint32(expRva + 12, 0x40, true);
  bytes[0x40] = 0x41;

  let sliceCalls = 0;
  const file = {
    lastModified: 0,
    name: "exports-eof-string.bin",
    size: bytes.length,
    type: "application/octet-stream",
    webkitRelativePath: "",
    slice(start?: number, end?: number, contentType?: string): Blob {
      sliceCalls += 1;
      if (sliceCalls > 4) {
        throw new Error("Too many export string reads");
      }
      const sliceStart = Math.max(0, Math.trunc(start ?? 0));
      const sliceEnd = Math.max(sliceStart, Math.trunc(end ?? bytes.length));
      const actualStart = Math.min(sliceStart, bytes.length);
      const actualEnd = Math.min(sliceEnd, bytes.length);
      return new Blob([bytes.slice(actualStart, actualEnd)], {
        type: contentType ?? "application/octet-stream"
      });
    }
  } as File;

  const result = await parseExportDirectory(
    file,
    [{ name: "EXPORT", rva: expRva, size: 40 }],
    value => value,
    () => {}
  );

  assert.equal(expectDefined(result).dllName, "A");
});
