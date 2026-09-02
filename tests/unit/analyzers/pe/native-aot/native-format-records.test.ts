"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { NativeFormatReader } from
  "../../../../../analyzers/pe/native-aot/native-format-reader.js";
import {
  NATIVE_FORMAT_SCOPE_HANDLE,
  parseNativeFormatMethodName,
  parseNativeFormatNamespaceRecord,
  parseNativeFormatScopeRecord,
  parseNativeFormatTypeRecord
} from "../../../../../analyzers/pe/native-aot/native-format-records.js";
import { createNativeFormatMetadataFixture } from
  "../../../../helpers/native-format-metadata-fixture.js";

const fixtureRoot = (majorVersion = 1) => {
  const reader = new NativeFormatReader(createNativeFormatMetadataFixture(majorVersion));
  const scopeHandle = reader.handles(4, [NATIVE_FORMAT_SCOPE_HANDLE], 1).value[0]!;
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

void test("NativeFormat scope records reject oversized UInt16 version components", () => {
  const { reader, scopeHandle } = fixtureRoot(0x1_0000);

  assert.throws(() => parseNativeFormatScopeRecord(reader, scopeHandle), /exceeds UInt16/);
});

void test("NativeFormat scope records accept the UInt16 version boundary", () => {
  const { reader, scopeHandle } = fixtureRoot(0xffff);

  assert.equal(parseNativeFormatScopeRecord(reader, scopeHandle).version.major, 0xffff);
});
