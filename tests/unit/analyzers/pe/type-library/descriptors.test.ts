import assert from "node:assert/strict";
import { test } from "node:test";
import { MsftTypeDescriptors, variantTypeName } from "../../../../../analyzers/pe/type-library/descriptors.js";
import { createDescriptorChain, createLibraryReader } from "../../../../fixtures/type-library.js";

void test("descriptors decode inline scalar and unknown VARTYPE values", () => {
  const descriptors = new MsftTypeDescriptors(createLibraryReader("TypdescTab"));
  assert.equal(descriptors.read(-2147483623), "HRESULT");
  assert.equal(variantTypeName(999), "VARTYPE(999)");
});

for (const [kind, expected] of [[26, "long*"], [27, "SAFEARRAY(long)"],
  [29, "href(-2147483645)"], [3, "long"]] as const) {
  void test(`descriptor resolves kind ${kind}`, () => {
    const reader = createLibraryReader("TypdescTab", 8);
    reader.view.setUint16(0, kind, true);
    reader.view.setInt32(4, -2147483645, true);
    const descriptors = new MsftTypeDescriptors(reader);
    assert.equal(descriptors.read(0), expected);
    assert.equal(descriptors.read(0), expected);
  });
}

for (const target of [0, 1, 128]) {
  void test(`descriptors reject cycle, unaligned offset or missing record (${target})`, () => {
    const reader = createLibraryReader("TypdescTab", 8);
    reader.view.setUint16(0, 26, true);
    reader.view.setInt32(4, target, true);
    assert.match(new MsftTypeDescriptors(reader).read(0), /invalid/);
    assert.ok(reader.issues.length);
  });
}

void test("C arrays decode element type, lower bounds and dimensions", () => {
  const reader = createLibraryReader("TypdescTab", 32);
  reader.segments.push({ name: "ArrayDescriptions", offset: 8, length: 24 });
  reader.view.setUint16(0, 28, true);
  reader.view.setInt32(8, -2147483645, true);
  reader.view.setUint16(12, 2, true);
  reader.view.setUint32(16, 3, true);
  reader.view.setInt32(20, -1, true);
  reader.view.setUint32(24, 5, true);
  assert.equal(new MsftTypeDescriptors(reader).read(0), "long[-1..1][0..4]");
});

for (const dimensions of [0, 0xffff, 2]) {
  void test(`array rejects invalid or truncated dimensions (${dimensions})`, () => {
    const reader = createLibraryReader("TypdescTab", 16);
    reader.segments.push({ name: "ArrayDescriptions", offset: 8, length: 8 });
    reader.view.setUint16(0, 28, true);
    reader.view.setUint16(12, dimensions, true);
    assert.equal(new MsftTypeDescriptors(reader).read(0), "invalid array");
    assert.ok(reader.issues.length);
  });
}

void test("array descriptor requires its referenced segment", () => {
  const reader = createLibraryReader("TypdescTab", 8);
  reader.view.setUint16(0, 28, true);
  assert.equal(new MsftTypeDescriptors(reader).read(0), "invalid array");
});

void test("shared descriptor nodes are decoded once across different root types", context => {
  const reader = createLibraryReader("TypdescTab", 24);
  reader.view.setUint16(0, 26, true);
  reader.view.setInt32(4, 16, true);
  reader.view.setUint16(8, 27, true);
  reader.view.setInt32(12, 16, true);
  reader.view.setUint16(16, 3, true);
  const reads = context.mock.method(reader.view, "getUint16");
  const descriptors = new MsftTypeDescriptors(reader);
  assert.equal(descriptors.read(0), "long*");
  assert.equal(descriptors.read(8), "SAFEARRAY(long)");
  assert.equal(reads.mock.callCount(), 3);
});

void test("shared array bounds are decoded once across different descriptors", context => {
  const reader = createLibraryReader("TypdescTab", 40);
  reader.segments.push({ name: "ArrayDescriptions", offset: 16, length: 24 });
  reader.view.setUint16(0, 28, true);
  reader.view.setUint16(8, 28, true);
  reader.view.setInt32(16, -2147483645, true);
  reader.view.setUint16(20, 1, true);
  const reads = context.mock.method(reader.view, "getUint16");
  const descriptors = new MsftTypeDescriptors(reader);
  assert.equal(descriptors.read(0), "long[0..-1]");
  assert.equal(descriptors.read(8), "long[0..-1]");
  assert.equal(reads.mock.callCount(), 3);
});

void test("iterative traversal preserves nesting order of pointers and safearrays", () => {
  const reader = createDescriptorChain(3);
  reader.view.setUint16(8, 27, true);
  assert.equal(new MsftTypeDescriptors(reader).read(0), "SAFEARRAY(long*)*");
});
