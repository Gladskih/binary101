"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseDelayImports32,
  parseDelayImports64
} from "../../analyzers/pe/delay-imports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import {
  IMAGE_DELAYLOAD_DESCRIPTOR_SIZE,
  IMAGE_THUNK_DATA32_SIZE,
  createDelayImportLayout,
  imageImportByNameSize,
  writeDelayImportDescriptor,
  writeDelayImportName,
  writeImportByName,
  writeThunkTable32
} from "./pe.delay-import-layout.js";

void test("parseDelayImports reads delay descriptors, names, and ordinals", async () => {
  const delayImportName = "kernel32.dll";
  const importHint = 0x1234; // Deliberately non-trivial to catch little-endian hint decoding.
  const layout = createDelayImportLayout(0x40);
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const hintNameRva = layout.reserve(imageImportByNameSize("Func"));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 3);
  const dllNameRva = layout.reserve(delayImportName.length + 1);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const dv = new DataView(bytes.buffer);
  // The parser exposes the raw TimeDateStamp field, so use a patterned value
  // that reveals byte-order bugs.
  const timeDateStamp = 0x12345678;
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: thunkTableRva,
    timeDateStamp
  });
  writeThunkTable32(dv, thunkTableRva, [hintNameRva, 0x80000002, 0]);
  writeImportByName(bytes, dv, hintNameRva, importHint, "Func");
  writeDelayImportName(bytes, dllNameRva, delayImportName);

  const coverageRegions: Array<{ label: string; start: number; size: number }> = [];
  const result = await parseDelayImports32(
    new MockFile(bytes, "delay-imports.bin"),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value,
    (label, start, size) => coverageRegions.push({ label, start, size })
  );

  const definedResult = expectDefined(result);
  assert.equal(coverageRegions.length, 1);
  const entry = expectDefined(definedResult.entries[0]);
  assert.equal(entry.name, delayImportName);
  assert.equal(entry.TimeDateStamp, timeDateStamp);
  assert.equal(entry.functions.length, 2);
  assert.deepEqual(entry.functions[0], { hint: importHint, name: "Func" });
  assert.deepEqual(entry.functions[1], { ordinal: 2 });
});

void test("parseDelayImports preserves a declared directory smaller than one delay descriptor with a warning", async () => {
  const bytes = new Uint8Array(64).fill(0);

  const result = await parseDelayImports32(
    new MockFile(bytes, "delay-imports-too-small.bin"),
    [{ name: "DELAY_IMPORT", rva: 0x10, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE - 1 }],
    value => value,
    () => {}
  );

  assert.ok(result);
  assert.deepEqual(result.entries, []);
  assert.ok(result.warning && /delay import|descriptor|truncated/i.test(result.warning));
});

void test("parseDelayImports warns when 32-bit thunk table truncates mid-entry", async () => {
  const bytes = new Uint8Array(0x54).fill(0);
  const dv = new DataView(bytes.buffer);
  const descriptorOffset = 0x10;
  const dllNameRva = 0x30;
  const thunkTableRva = 0x50;
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: thunkTableRva
  });
  writeDelayImportName(bytes, dllNameRva, "delay.dll");
  writeThunkTable32(dv, thunkTableRva, [0x80000002]);

  const result = await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 1);
  assert.ok(definedResult.warning?.toLowerCase().includes("thunk table truncated"));
});

void test("parseDelayImports tolerates truncated INT in 64-bit path", async () => {
  const bytes = new Uint8Array(0x54).fill(0);
  const dv = new DataView(bytes.buffer);
  const descriptorOffset = 0x10;
  const dllNameRva = 0x30;
  const thunkTableRva = 0x50;
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: thunkTableRva
  });
  writeDelayImportName(bytes, dllNameRva, "delay.dll");
  writeThunkTable32(dv, thunkTableRva, [0xdeadbeef]);

  const result = await parseDelayImports64(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 1);
  const entry = expectDefined(definedResult.entries[0]);
  assert.equal(entry.functions.length, 0);
  assert.ok(definedResult.warning?.toLowerCase().includes("thunk table truncated"));
});

void test("parseDelayImports handles an empty INT in the 32-bit path", async () => {
  const bytes = new Uint8Array(96).fill(0);
  const dv = new DataView(bytes.buffer);
  const descriptorOffset = 0x10;
  const dllNameRva = 0x30;
  const thunkTableRva = 0x50;
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: thunkTableRva
  });
  writeDelayImportName(bytes, dllNameRva, "delay.dll");
  writeThunkTable32(dv, thunkTableRva, [0]);

  const result = await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 1);
  const entry = expectDefined(definedResult.entries[0]);
  assert.equal(entry.functions.length, 0);
  assert.equal(definedResult.warning, undefined);
});

void test("parseDelayImports handles truncated hint/name strings", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const descriptorOffset = 0x20;
  const dllNameRva = 0x40;
  const thunkTableRva = 0x60;
  const truncatedHintNameRva = 0x78;
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: thunkTableRva
  });
  writeDelayImportName(bytes, dllNameRva, "delay.dll");
  writeThunkTable32(dv, thunkTableRva, [truncatedHintNameRva]);
  dv.setUint16(0x78, 0x7f7f, true);
  bytes.fill(0x41, 0x7a);

  const result = await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 1);
  const entry = expectDefined(definedResult.entries[0]);
  assert.ok(entry.functions.length >= 1);
  const firstFunction = expectDefined(entry.functions[0]);
  assert.ok(typeof firstFunction.name === "string");
  assert.ok(definedResult.warning?.toLowerCase().includes("name string truncated"));
});

void test("parseDelayImports treats descriptor fields as RVA when Attributes is zero", async () => {
  const layout = createDelayImportLayout(0x40);
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = layout.reserve("kernel32.dll".length + 1);
  const intRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 2);
  const hintNameRva = layout.reserve(imageImportByNameSize("Func"));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const dv = new DataView(bytes.buffer);
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: intRva
  });
  writeThunkTable32(dv, intRva, [hintNameRva, 0]);
  writeImportByName(bytes, dv, hintNameRva, 0x10, "Func");
  writeDelayImportName(bytes, dllNameRva, "kernel32.dll");

  const result = await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  const entry = expectDefined(definedResult.entries[0]);
  assert.deepEqual(entry.functions, [{ hint: 0x10, name: "Func" }]);
});

void test("parseDelayImports warns when a mapped DLL name offset falls past EOF", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const descriptorOffset = 0x20;
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva: 0x40,
    importNameTableRva: 0
  });

  const result = expectDefined(await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => (value === descriptorOffset ? descriptorOffset : value === 0 ? null : value + 0x200),
    () => {}
  ));

  assert.ok(result.warning?.toLowerCase().includes("name rva"));
});

void test("parseDelayImports warns when a hint/name entry is shorter than two bytes", async () => {
  const bytes = new Uint8Array(0x81).fill(0);
  const dv = new DataView(bytes.buffer);
  const descriptorOffset = 0x20;
  const dllNameRva = 0x40;
  const thunkTableRva = 0x60;
  const truncatedHintNameRva = 0x80;
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: thunkTableRva
  });
  writeDelayImportName(bytes, dllNameRva, "delay.dll");
  writeThunkTable32(dv, thunkTableRva, [truncatedHintNameRva]);

  const result = expectDefined(await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  ));

  assert.ok(result.warning?.toLowerCase().includes("truncated"));
});

void test("parseDelayImports warns when Delay-Load Attributes is non-zero", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const descriptorOffset = 0x20;
  const dllNameRva = 0x60;
  const thunkTableRva = 0x70;
  // Microsoft PE Format, "The Delay-Load Directory Table": Attributes must be zero in the image.
  writeDelayImportDescriptor(dv, descriptorOffset, {
    attributes: 1,
    dllNameRva,
    importNameTableRva: thunkTableRva
  });
  writeDelayImportName(bytes, dllNameRva, "delay.dll");
  writeThunkTable32(dv, thunkTableRva, [0]);

  const result = expectDefined(await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  ));

  assert.equal(result.entries[0]?.name, "delay.dll");
  assert.ok(result.warning?.toLowerCase().includes("attributes"));
});
