import assert from "node:assert/strict";
import { test } from "node:test";
import { readMembers } from "../../../../../analyzers/pe/type-library/members.js";
import { MsftTypeDescriptors } from "../../../../../analyzers/pe/type-library/descriptors.js";
import { createLibraryReader } from "../../../../fixtures/type-library.js";
import type { TypeLibraryReader } from "../../../../../analyzers/pe/type-library/reader.js";

const functionReader = (size: number, parameterCount = 0): TypeLibraryReader => {
  const reader = createLibraryReader("CustData", 256);
  reader.view.setUint32(0, size, true);
  reader.view.setUint32(4, size, true);
  reader.view.setInt32(8, -2147483623, true);
  reader.view.setUint16(24, parameterCount, true);
  reader.view.setInt32(4 + size, 7, true);
  reader.view.setInt32(8 + size, -1, true);
  reader.names.set(0, "param");
  reader.strings.set(0, "doc");
  reader.customData.set(0, [{ guid: "custom", value: { type: 3, value: 42 } }]);
  return reader;
};

const parseFunction = (reader: TypeLibraryReader) =>
  readMembers(reader, new MsftTypeDescriptors(reader), 0, 1, 0);

void test("functions parse optional attributes, defaults and per-argument custom data", () => {
  const reader = functionReader(80, 1);
  reader.view.setUint32(20, 0x1080, true);
  reader.view.setInt32(68, -1946157014, true);
  reader.view.setInt32(72, -2147483645, true);
  reader.view.setUint32(80, 0x20, true);
  const member = parseFunction(reader).functions[0];
  assert.equal(member?.documentation, "doc");
  assert.equal(member?.entry, "doc");
  assert.deepEqual(member?.customData, [{ guid: "custom", value: { type: 3, value: 42 } }]);
  assert.deepEqual(member?.parameters[0]?.defaultValue, { type: 3, value: 42 });
  assert.deepEqual(member?.parameters[0]?.customData, member?.customData);
});

void test("DLL functions can have numeric entry ordinals", () => {
  const reader = functionReader(36);
  reader.view.setUint32(20, 0x2000, true);
  reader.view.setUint32(36, 123, true);
  assert.equal(parseFunction(reader).functions[0]?.entry, 123);
});

void test("parameter tables cannot overlap the fixed function fields", () => {
  const reader = functionReader(24, 1);
  assert.deepEqual(parseFunction(reader).functions[0]?.parameters, []);
  assert.match(reader.issues.join(), /parameter.*truncated/);
});

void test("parser bounds-checks the member block and its index arrays", () => {
  const reader = functionReader(24);
  assert.deepEqual(readMembers(reader, new MsftTypeDescriptors(reader), -1, 1, 0).functions, []);
  reader.view.setUint32(0, 0xffffffff, true);
  assert.deepEqual(parseFunction(reader).functions, []);
  assert.match(reader.issues.join(), /index tables.*truncated/);
});

void test("member records enforce minimum fixed field sizes", () => {
  const reader = functionReader(20);
  assert.deepEqual(parseFunction(reader).functions, []);
  assert.match(reader.issues.join(), /invalid size/);
});

void test("member counts cannot exceed the physically present index arrays", () => {
  const reader = functionReader(24);
  assert.deepEqual(readMembers(reader, new MsftTypeDescriptors(reader), 0, 65535, 65535).functions, []);
  assert.match(reader.issues.join(), /index tables.*truncated/);
});

void test("variables expose instance offsets, documentation and custom data", () => {
  const reader = functionReader(40);
  reader.view.setUint16(16, 0, true);
  reader.view.setUint32(20, 12, true);
  const member = readMembers(reader, new MsftTypeDescriptors(reader), 0, 0, 1).variables[0];
  assert.equal(member?.instanceOffset, 12);
  assert.equal(member?.documentation, "doc");
  assert.equal(member?.helpContext, 0);
  assert.equal(member?.customData[0]?.guid, "custom");
});

const propertyPairReader = (): TypeLibraryReader => {
  const reader = functionReader(48);
  reader.view.setUint32(4, 24, true);
  reader.view.setUint32(20, 2 << 3, true);
  reader.view.setUint32(28, 24, true);
  reader.view.setInt32(32, -2147483623, true);
  reader.view.setUint32(44, 4 << 3, true);
  reader.view.setInt32(60, 0, true);
  reader.view.setInt32(64, -1, true);
  reader.view.setUint32(72, 24, true);
  return reader;
};

void test("property pairs reuse only the absent-name sentinel", () => {
  const reader = propertyPairReader();
  assert.equal(readMembers(reader, new MsftTypeDescriptors(reader), 0, 2, 0)
    .functions[1]?.name, "param");
});

void test("invalid property names cannot silently inherit the preceding name", () => {
  const reader = propertyPairReader();
  reader.view.setInt32(64, 999, true);
  assert.equal(readMembers(reader, new MsftTypeDescriptors(reader), 0, 2, 0)
    .functions[1]?.name, null);
  assert.match(reader.issues.join(), /name reference 999 is invalid/);
});
