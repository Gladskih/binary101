import assert from "node:assert/strict";
import { test } from "node:test";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { NativeFormatStore } from "../../../../analyzers/native-aot/native-format-store.js";
import { NativeFormatMembers } from "../../../../analyzers/native-aot/native-format-members.js";
import { createNativeFormatMemberFixture } from "../../../helpers/native-format-member-fixture.js";

void test("reads method flags, signatures, named parameters and generic constraints", () => {
  const fixture = createNativeFormatMemberFixture();
  const warnings = new Set<string>();
  const members = new NativeFormatMembers(new NativeFormatStore(
    new NativeFormatReader(fixture.bytes), warnings));

  const method = members.method(fixture.handle("method-member", 0x28));

  assert.equal(method?.name, "Convert");
  assert.equal(method?.flags, 6);
  assert.equal(method?.implementationFlags, 0);
  assert.deepEqual(method?.signature?.parameters, ["Demo.Item[]", "!0&"]);
  assert.deepEqual(method?.parameters, [{ name: "input", flags: 16, sequence: 1 }]);
  assert.deepEqual(method?.genericParameters,
    [{ name: "T", number: 0, flags: 4, kind: 1, constraints: ["Demo.Item"] }]);
  assert.equal(members.method(fixture.handle("method-member", 0x28)), method);
  assert.equal(warnings.size, 0);
});

void test("reads field types, offsets, property index signatures and accessor semantics", () => {
  const fixture = createNativeFormatMemberFixture();
  const warnings = new Set<string>();
  const members = new NativeFormatMembers(new NativeFormatStore(
    new NativeFormatReader(fixture.bytes), warnings));

  assert.deepEqual(members.field(fixture.handle("field", 0x23)),
    { name: "Value", flags: 6, type: "Demo.Item", offset: 12 });
  assert.deepEqual(members.property(fixture.handle("property", 0x33)), {
    name: "Item", flags: 0, callingConvention: 0x20, type: "Demo.Item", parameters: ["!!1"],
    semantics: [{ attributes: 2, method: "Convert" }]
  });
  assert.deepEqual(members.event(fixture.handle("event", 0x22)), {
    name: "Changed", flags: 0, type: "Demo.Item",
    semantics: [{ attributes: 2, method: "Convert" }]
  });
  assert.equal(warnings.size, 0);
});

void test("contains malformed member names and truncated records", () => {
  const warnings = new Set<string>();
  const members = new NativeFormatMembers(new NativeFormatStore(
    new NativeFormatReader(Uint8Array.of(0, 44, 0)), warnings));

  assert.deepEqual(members.field({ type: 0x23, offset: 1 }), { name: "", flags: 22 });
  assert.equal(members.method({ type: 0x28, offset: 3 }), null);
  assert.equal(members.method({ type: 0x28, offset: 3 }), null);
  assert.equal(warnings.size, 2);
});

void test("skips nil members and malformed parameter, generic and accessor records", () => {
  const warnings = new Set<string>();
  const members = new NativeFormatMembers(new NativeFormatStore(
    new NativeFormatReader(Uint8Array.of(0)), warnings));

  assert.equal(members.method({ type: 0x28, offset: 0 }), null);
  assert.equal(warnings.size, 0);
  assert.deepEqual(members.parameters([{ type: 0x31, offset: 1 }]), []);
  assert.deepEqual(members.generics([{ type: 0x26, offset: 1 }]), []);
  assert.deepEqual(members.semantics([{ type: 0x2a, offset: 1 }]), []);
  assert.match([...warnings].join(" "), /parameter.*could not be read/);
  assert.match([...warnings].join(" "), /generic parameter/);
  assert.match([...warnings].join(" "), /method semantics/);
});
