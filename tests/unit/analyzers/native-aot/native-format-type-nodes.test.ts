import assert from "node:assert/strict";
import { test } from "node:test";
import { readNativeFormatTypeNode } from
  "../../../../analyzers/native-aot/native-format-type-nodes.js";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { NativeFormatStore } from "../../../../analyzers/native-aot/native-format-store.js";
import { createNativeFormatTypeNodeFixture } from
  "../../../helpers/native-format-type-node-fixture.js";
import { createNativeFormatSignatureFixture } from
  "../../../helpers/native-format-signature-fixture.js";

void test("formats named definitions and nested types with their correct parents", () => {
  const fixture = createNativeFormatTypeNodeFixture();
  const outer = readNativeFormatTypeNode(fixture.store, fixture.handle("outer", 0x3a));
  const inner = readNativeFormatTypeNode(fixture.store, fixture.handle("inner", 0x3a));
  const namespace = readNativeFormatTypeNode(fixture.store, fixture.handle("namespace", 0x2f));

  assert.deepEqual(outer.dependencies, [fixture.handle("namespace", 0x2f)]);
  assert.equal(outer.format(["Demo"]), "Demo.Outer");
  assert.deepEqual(inner.dependencies, [fixture.handle("outer", 0x3a)]);
  assert.equal(inner.format(["Demo.Outer"]), "Demo.Outer+Inner");
  assert.equal(namespace.format([]), "Demo");
  assert.equal(fixture.warnings.size, 0);
});

void test("formats scopes as namespace roots and rejects unsupported signature kinds", () => {
  const store = new NativeFormatStore(new NativeFormatReader(new Uint8Array(32)), new Set());

  assert.equal(readNativeFormatTypeNode(store, { type: 0x38, offset: 1 }).format([]), "");
  assert.equal(readNativeFormatTypeNode(store, { type: 0x39, offset: 1 }).format([]), "");
  assert.throws(() => readNativeFormatTypeNode(store, { type: 0x23, offset: 1 }),
    /Unexpected type-signature handle/);
});

void test("rejects invalid dimensions while describing extreme ranks without expansion", () => {
  // ArraySignature: nil element, rank, sizes count, lower-bounds count.
  const store = new NativeFormatStore(new NativeFormatReader(
    Uint8Array.of(0, 0, 0, 0, 0, 0, 2, 4, 2, 4, 0, 0, 2, 0, 4, 0, 0,
      0, 0x0f, 0xff, 0xff, 0xff, 0xff, 0, 0)), new Set());

  assert.throws(() => readNativeFormatTypeNode(store, { type: 1, offset: 1 }), /rank/);
  assert.throws(() => readNativeFormatTypeNode(store, { type: 1, offset: 5 }), /rank/);
  assert.throws(() => readNativeFormatTypeNode(store, { type: 1, offset: 11 }), /rank/);
  assert.equal(readNativeFormatTypeNode(store, { type: 1, offset: 17 }).format(["T"]),
    "T[rank=4294967295; sizes=; lowerBounds=]");
});

void test("formats required modifiers, nested references and varargs without fixed parameters", () => {
  const fixture = createNativeFormatSignatureFixture();
  const store = new NativeFormatStore(new NativeFormatReader(fixture.bytes), new Set());
  store.record(fixture.handle("modified", 0x2d)).values["isOptional"] = 0;
  store.record(fixture.handle("method", 0x2b)).values["parameters"] = [];
  store.record(fixture.handle("type", 0x3d)).values["parent"] = { type: 0x3d, offset: 1 };

  assert.equal(readNativeFormatTypeNode(store, fixture.handle("modified", 0x2d))
    .format(["T", "M"]), "T modreq(M)");
  assert.equal(readNativeFormatTypeNode(store, fixture.handle("method", 0x2b))
    .format(["T", "V"]), "fnptr[0x20; arity=1] T(..., V)");
  assert.equal(readNativeFormatTypeNode(store, fixture.handle("type", 0x3d))
    .format(["Outer"]), "Outer+Item");
});

void test("accepts complete array dimensions and function pointers without varargs", () => {
  const store = new NativeFormatStore(new NativeFormatReader(
    Uint8Array.of(0, 0, 2, 2, 8, 2, 0)), new Set());
  const fixture = createNativeFormatSignatureFixture();
  const signatures = new NativeFormatStore(new NativeFormatReader(fixture.bytes), new Set());
  signatures.record(fixture.handle("method", 0x2b)).values["varArgParameters"] = [];

  assert.equal(readNativeFormatTypeNode(store, { type: 1, offset: 1 }).format(["T"]),
    "T[rank=1; sizes=4; lowerBounds=0]");
  assert.equal(readNativeFormatTypeNode(signatures, fixture.handle("method", 0x2b))
    .format(["T", "P", "Q"]), "fnptr[0x20; arity=1] T(P, Q)");
});
