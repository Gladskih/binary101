import assert from "node:assert/strict";
import test from "node:test";
import { skipReadyToRunMethodSignature } from "../../../../../analyzers/pe/clr/ready-to-run-method-signature.js";

void test("locates the native entrypoint after a generic R2R method signature", () => {
  // Flags: owner type + method instantiation, class TypeDef RID 1, MethodDef RID 2,
  // two type arguments (Int32, SZArray<String>). The trailing 99 is not part of the signature.
  const bytes = Uint8Array.of(0x44, 0x12, 4, 2, 2, 8, 0x1d, 14, 99);

  assert.equal(skipReadyToRunMethodSignature(bytes, 0), 8);
});

void test("consumes module context, owner type, MemberRef, constrained type and stub flags", () => {
  const bytes = Uint8Array.of(0x80, 0xf3, 1, 0x12, 4, 2, 0x1d, 8, 99);

  assert.equal(skipReadyToRunMethodSignature(bytes, 0), 8);
});

void test("consumes an owner type followed by a slot index without requiring metadata binding", () => {
  assert.equal(skipReadyToRunMethodSignature(Uint8Array.of(0x48, 0x12, 4, 7), 0), 4);
  assert.equal(skipReadyToRunMethodSignature(Uint8Array.of(0, 0x81, 1), 0), 3);
});

void test("rejects unknown method flags and malformed generic type sequences", () => {
  assert.throws(() => skipReadyToRunMethodSignature(Uint8Array.of(0x81, 0), 0), /flags/);
  assert.throws(() => skipReadyToRunMethodSignature(Uint8Array.of(4, 1, 2, 8), 0), /count exceeds/);
  assert.throws(() => skipReadyToRunMethodSignature(Uint8Array.of(0x40, 0x40), 0), /Unsupported/);
});

void test("accepts the boundary containing all currently defined method flag bits", () => {
  // Compressed 0xff flags, module context, owner class, slot, one Int32 argument, constrained Int32.
  // ReadyToRunMethodSigFlags in ReadyToRunConstants.cs, dotnet/runtime v10.0.0.
  const bytes = Uint8Array.of(0x80, 0xff, 1, 0x12, 4, 7, 1, 8, 8);

  assert.equal(skipReadyToRunMethodSignature(bytes, 0), 9);
});
