"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseBoundImports } from "../../analyzers/pe/bound-imports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();
const IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE = 8; // IMAGE_BOUND_IMPORT_DESCRIPTOR

type BoundImportDescriptorFixture = {
  timeDateStamp: number;
  moduleName?: string;
  forwarderRefCount?: number;
  nameOffset?: number;
};

const writeBoundImportDescriptor = (
  view: DataView,
  offset: number,
  timeDateStamp: number,
  nameOffset: number,
  forwarderRefCount: number
): void => {
  view.setUint32(offset, timeDateStamp, true);
  view.setUint16(offset + Uint32Array.BYTES_PER_ELEMENT, nameOffset, true);
  view.setUint16(offset + 6, forwarderRefCount, true);
};

const createBoundImportDirectory = (
  descriptors: BoundImportDescriptorFixture[],
  directoryOffset: number,
  declaredDirectorySize: number,
  fileSize = 0x100
): Uint8Array => {
  const bytes = new Uint8Array(fileSize).fill(0);
  const view = new DataView(bytes.buffer);
  let nextNameOffset = (descriptors.length + 1) * IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE;
  descriptors.forEach((descriptor, index) => {
    const descriptorOffset = directoryOffset + index * IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE;
    const nameOffset = descriptor.moduleName
      ? (descriptor.nameOffset ?? nextNameOffset)
      : (descriptor.nameOffset ?? 0);
    writeBoundImportDescriptor(
      view,
      descriptorOffset,
      descriptor.timeDateStamp,
      nameOffset,
      descriptor.forwarderRefCount ?? 0
    );
    if (descriptor.moduleName) {
      encoder.encodeInto(
        `${descriptor.moduleName}\0`,
        new Uint8Array(bytes.buffer, directoryOffset + nameOffset)
      );
    }
    if (descriptor.moduleName && descriptor.nameOffset == null) {
      nextNameOffset += encoder.encode(`${descriptor.moduleName}\0`).length;
    }
  });
  if (directoryOffset + declaredDirectorySize <= bytes.length) {
    bytes.fill(0, directoryOffset + declaredDirectorySize);
  }
  return bytes;
};

void test("parseBoundImports extracts bound import names", async () => {
  const directoryOffset = 0x20;
  // Use a patterned timestamp so byte-order mistakes are obvious.
  const bytes = createBoundImportDirectory(
    [{ timeDateStamp: 0x01020304, moduleName: "USER32.dll" }],
    directoryOffset,
    0x40,
    0x80
  );

  const result = await parseBoundImports(
    new MockFile(bytes, "bound-imports.bin"),
    [{ name: "BOUND_IMPORT", rva: directoryOffset, size: 0x40 }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 1);
  const entry = expectDefined(definedResult.entries[0]);
  assert.equal(entry.name, "USER32.dll");
  assert.equal(entry.TimeDateStamp, 0x01020304);
});

void test("parseBoundImports stops on truncated descriptor", async () => {
  const base = 16;
  const bytes = new Uint8Array(18).fill(0); // less than one full descriptor
  const result = await parseBoundImports(
    new MockFile(bytes),
    [{ name: "BOUND_IMPORT", rva: base, size: 8 }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 0);
  assert.ok(definedResult.warning?.toLowerCase().includes("truncated"));
});

void test("parseBoundImports handles name offset outside directory", async () => {
  const directoryOffset = 0x20;
  const bytes = createBoundImportDirectory(
    [{ timeDateStamp: 1, nameOffset: 0x80 }],
    directoryOffset,
    0x10
  );

  const result = await parseBoundImports(
    new MockFile(bytes),
    [{ name: "BOUND_IMPORT", rva: directoryOffset, size: 0x10 }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 1);
  assert.equal(definedResult.entries[0]?.name, "");
  assert.ok(definedResult.warning?.toLowerCase().includes("name offset"));
});

void test("parseBoundImports skips over forwarder refs before the next descriptor", async () => {
  const directoryOffset = 0x40;
  const bytes = createBoundImportDirectory(
    [
      { timeDateStamp: 1, moduleName: "KERNEL32.dll", forwarderRefCount: 1 },
      { timeDateStamp: 2, moduleName: "NTDLL.dll" },
      { timeDateStamp: 3, moduleName: "USER32.dll" }
    ],
    directoryOffset,
    0x60
  );

  const result = await parseBoundImports(
    new MockFile(bytes),
    [{ name: "BOUND_IMPORT", rva: directoryOffset, size: 0x60 }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.deepEqual(
    definedResult.entries.map(entry => entry.name),
    ["KERNEL32.dll", "USER32.dll"]
  );
});

void test("parseBoundImports clamps module names to the declared directory span", async () => {
  const directoryOffset = 0x20;
  // 20 bytes = 8-byte descriptor + 8-byte zero terminator + 4 bytes left for the name payload.
  const directorySize = 20;
  const bytes = createBoundImportDirectory(
    [{ timeDateStamp: 1, moduleName: "ABCDEF", nameOffset: 16 }],
    directoryOffset,
    directorySize
  );

  const result = await parseBoundImports(
    new MockFile(bytes),
    [{ name: "BOUND_IMPORT", rva: directoryOffset, size: directorySize }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 1);
  assert.equal(definedResult.entries[0]?.name, "ABCD");
  assert.ok(definedResult.warning?.toLowerCase().includes("name"));
});
