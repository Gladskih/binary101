"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { NativeFormatReader } from
  "../../../../analyzers/native-aot/native-format-reader.js";
import {
  NATIVE_FORMAT_SCOPE_HANDLE,
  parseNativeFormatFieldName,
  parseNativeFormatMethodName,
  parseNativeFormatNamespaceRecord,
  parseNativeFormatScopeRecord,
  parseNativeFormatTypeRecord
} from "../../../../analyzers/native-aot/native-format-records.js";
import { createNativeFormatMetadataFixture } from
  "../../../helpers/native-format-metadata-fixture.js";

const fixtureRoot = (majorVersion = 1) => {
  const reader = new NativeFormatReader(createNativeFormatMetadataFixture(majorVersion));
  const scopeHandle = reader.handles(4, [NATIVE_FORMAT_SCOPE_HANDLE]).value[0]!;
  return { reader, scopeHandle };
};

void test("NativeFormat record readers follow scope, namespace, type, and method records", () => {
  const { reader, scopeHandle } = fixtureRoot();

  const scope = parseNativeFormatScopeRecord(reader, scopeHandle);
  const rootNamespace = parseNativeFormatNamespaceRecord(reader, scope.rootNamespace);
  const demoNamespace = parseNativeFormatNamespaceRecord(reader, rootNamespace.children[0]!);
  const program = parseNativeFormatTypeRecord(reader, demoNamespace.types[0]!);
  const nested = parseNativeFormatTypeRecord(reader, program.nestedTypes[0]!);

  assert.equal(reader.string(scope.name), "HelloCSharp");
  assert.equal(reader.string(demoNamespace.name), "Demo");
  assert.equal(reader.string(program.name), "Program");
  assert.equal(reader.string(nested.name), "Nested");
  assert.equal(parseNativeFormatMethodName(reader, program.methods[0]!), "Main");
});

void test("NativeFormat reads a field name without requiring an unused signature tail", () => {
  // Field flags Public|Static, typed name offset 3, UTF-8 length 5; NativeFormatReaderGen.cs.
  const reader = new NativeFormatReader(Uint8Array.from([0, 0x2c, 6, 10, ...Buffer.from("Count")]));

  assert.equal(parseNativeFormatFieldName(reader, { type: 0x23, offset: 1 }), "Count");
});

void test("NativeFormat accepts a nil field name", () => {
  const reader = new NativeFormatReader(Uint8Array.from([0, 0, 0]));

  assert.equal(parseNativeFormatFieldName(reader, { type: 0x23, offset: 1 }), "");
});

const malformedFields = [
  { name: "negative record offset", bytes: [0], offset: -1 },
  { name: "extreme record offset", bytes: [0], offset: Number.MAX_SAFE_INTEGER },
  { name: "truncated flags", bytes: [0, 0x0f], offset: 1 },
  { name: "invalid flags encoding", bytes: [0, 0xff], offset: 1 },
  { name: "missing name handle", bytes: [0, 0], offset: 1 },
  { name: "name outside metadata", bytes: [0, 0, 6], offset: 1 },
  { name: "truncated name bytes", bytes: [0, 0, 6, 4, 65], offset: 1 },
  { name: "invalid UTF-8 name", bytes: [0, 0, 6, 2, 0xff], offset: 1 }
];

for (const entry of malformedFields) {
  void test(`NativeFormat rejects field ${entry.name}`, () => {
    const reader = new NativeFormatReader(Uint8Array.from(entry.bytes));

    assert.throws(() => parseNativeFormatFieldName(reader, { type: 0x23, offset: entry.offset }));
  });
}

void test("NativeFormat scope records reject oversized UInt16 version components", () => {
  const { reader, scopeHandle } = fixtureRoot(0x1_0000);

  assert.throws(() => parseNativeFormatScopeRecord(reader, scopeHandle), /exceeds UInt16/);
});

void test("NativeFormat scope records accept the UInt16 version boundary", () => {
  const { reader, scopeHandle } = fixtureRoot(0xffff);

  assert.equal(parseNativeFormatScopeRecord(reader, scopeHandle).version.major, 0xffff);
});
