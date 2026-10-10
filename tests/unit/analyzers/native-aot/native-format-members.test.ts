import assert from "node:assert/strict";
import { test } from "node:test";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { NativeFormatStore } from "../../../../analyzers/native-aot/native-format-store.js";
import { NativeFormatMembers } from "../../../../analyzers/native-aot/native-format-members.js";
import { createNativeFormatMemberFixture } from "../../../helpers/native-format-member-fixture.js";

// Member record tags are generated NativeFormat HandleType values, mirrored in the fixture oracle.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs
const memberType = {
  event: 0x22, field: 0x23, method: 0x28, semantics: 0x2a,
  parameter: 0x31, property: 0x33, genericParameter: 0x26
} as const;

void test("reads method flags, signatures, named parameters and generic constraints", () => {
  const fixture = createNativeFormatMemberFixture();
  const warnings = new Set<string>();
  const members = new NativeFormatMembers(new NativeFormatStore(
    new NativeFormatReader(fixture.bytes), warnings));

  const method = members.method(fixture.handle("method-member", memberType.method));

  assert.equal(method?.name, "Convert");
  assert.equal(method?.flags, 6); // mdPublic access mask from the fixture's source-backed writer.
  assert.equal(method?.implementationFlags, 0);
  assert.deepEqual(method?.signature?.parameters, ["Demo.Item[]", "!0&"]);
  assert.deepEqual(method?.parameters, [{ name: "input", flags: 16, sequence: 1, attributes: [] }]);
  assert.deepEqual(method?.genericParameters,
    [{ name: "T", number: 0, flags: 4, kind: 1, constraints: ["Demo.Item"], attributes: [] }]);
  assert.equal(members.method(fixture.handle("method-member", memberType.method)), method);
  assert.equal(warnings.size, 0);
});

void test("reads field types, offsets, property index signatures and accessor semantics", () => {
  const fixture = createNativeFormatMemberFixture();
  const warnings = new Set<string>();
  const members = new NativeFormatMembers(new NativeFormatStore(
    new NativeFormatReader(fixture.bytes), warnings));

  assert.deepEqual(members.field(fixture.handle("field", memberType.field)),
    { name: "Value", flags: 6, type: "Demo.Item", offset: 12, attributes: [] });
  // MethodSemantics.Getter is 2; AddOn is 8 for the event's add accessor.
  assert.deepEqual(members.property(fixture.handle("property", memberType.property)), {
    name: "Item", flags: 0, callingConvention: 0x20, type: "Demo.Item", parameters: ["!!1"],
    semantics: [{ attributes: 2, method: "Convert" }], attributes: []
  });
  assert.deepEqual(members.event(fixture.handle("event", memberType.event)), {
    name: "Changed", flags: 0, type: "Demo.Item",
    semantics: [{ attributes: 8, method: "Convert" }], attributes: []
  });
  assert.equal(warnings.size, 0);
});

void test("contains malformed member names and truncated records", () => {
  const warnings = new Set<string>();
  // Field flags 22 = mdPublic | mdStatic; then a nil name and no signature tail.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/cor.h
  const members = new NativeFormatMembers(new NativeFormatStore(
    new NativeFormatReader(Uint8Array.of(0, 44, 0)), warnings));

  assert.deepEqual(members.field({ type: memberType.field, offset: 1 }), { name: "", flags: 22 });
  // Offset 3 is exactly the exclusive end of this byte array; repeated reads reuse the cached failure.
  assert.equal(members.method({ type: memberType.method, offset: 3 }), null);
  assert.equal(members.method({ type: memberType.method, offset: 3 }), null);
  assert.equal(warnings.size, 2);
});

void test("skips nil members and malformed parameter, generic and accessor records", () => {
  const warnings = new Set<string>();
  const members = new NativeFormatMembers(new NativeFormatStore(
    new NativeFormatReader(Uint8Array.of(0)), warnings));

  assert.equal(members.method({ type: memberType.method, offset: 0 }), null);
  assert.equal(warnings.size, 0);
  assert.deepEqual(members.parameters([{ type: memberType.parameter, offset: 1 }]), []);
  assert.deepEqual(members.generics([{ type: memberType.genericParameter, offset: 1 }]), []);
  assert.deepEqual(members.semantics([{ type: memberType.semantics, offset: 1 }]), []);
  assert.match([...warnings].join(" "), /parameter.*could not be read/);
  assert.match([...warnings].join(" "), /generic parameter/);
  assert.match([...warnings].join(" "), /method semantics/);
});
