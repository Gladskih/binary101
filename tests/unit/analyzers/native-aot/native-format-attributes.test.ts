import assert from "node:assert/strict";
import test from "node:test";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { NativeFormatStore } from "../../../../analyzers/native-aot/native-format-store.js";
import { NativeFormatMembers } from "../../../../analyzers/native-aot/native-format-members.js";
import { createNativeFormatAttributeFixture } from "../../../helpers/native-format-attribute-fixture.js";

void test("attributes decode member-reference constructors, typed fixed values and named fields/properties", () => {
  const fixture = createNativeFormatAttributeFixture();
  const warnings = new Set<string>();
  const members = new NativeFormatMembers(new NativeFormatStore(new NativeFormatReader(fixture.bytes), warnings));

  const attribute = members.attributes.read(fixture.handle("attribute", 0x21))!;

  assert.equal(attribute.type, "ExampleAttribute");
  assert.equal(attribute.constructorName, ".ctor");
  assert.deepEqual(attribute.fixedArguments, [
    { type: "long", value: "9007199254740993" }, { type: "ExampleAttribute", value: 42 },
    { type: "string[]", value: [{ type: "string", value: "<hello>" }, { type: "object", value: null },
      { type: "object", value: null }] }, { type: "Type", value: "ExampleAttribute" },
    { type: "ExampleAttribute[]", value: [{ type: "int", value: 42 }, { type: "int", value: 43 }] }
  ]);
  assert.deepEqual(attribute.namedArguments, [
    { kind: "field", name: "Number", type: "ExampleAttribute", value: { type: "int", value: 42 } },
    { kind: "property", name: "Enabled", type: "ExampleAttribute", value: { type: "bool", value: false } }
  ]);
  assert.equal(members.attributes.read(fixture.handle("attribute", 0x21)), attribute);
  assert.equal(warnings.size, 0);
});

void test("qualified constructors and owner defaults retain exact values and attribute ownership", () => {
  const fixture = createNativeFormatAttributeFixture();
  const warnings = new Set<string>();
  const members = new NativeFormatMembers(new NativeFormatStore(new NativeFormatReader(fixture.bytes), warnings));

  assert.deepEqual(members.attributes.read(fixture.handle("qualified-attribute", 0x21)),
    { type: "ExampleAttribute", constructorName: ".ctor", fixedArguments: [], namedArguments: [] });
  assert.deepEqual(members.field(fixture.handle("field", 0x23))?.defaultValue,
    { type: "long", value: "9007199254740993" });
  assert.deepEqual(members.property(fixture.handle("property", 0x33))?.defaultValue, { type: "int", value: 42 });
  assert.deepEqual(members.parameters([fixture.handle("parameter", 0x31)])[0]?.defaultValue,
    { type: "bool", value: false });
  assert.equal(members.field(fixture.handle("field", 0x23))?.attributes?.[0]?.type, "ExampleAttribute");
  assert.equal(members.parameters([fixture.handle("parameter", 0x31)])[0]?.attributes?.length, 1);
  assert.equal(warnings.size, 0);
});

void test("malformed named arguments preserve the constructor and other arguments", () => {
  const fixture = createNativeFormatAttributeFixture();
  fixture.bytes[fixture.handle("named-field", 0x2e).offset] = 4;
  const warnings = new Set<string>();
  const members = new NativeFormatMembers(new NativeFormatStore(new NativeFormatReader(fixture.bytes), warnings));

  const attribute = members.attributes.read(fixture.handle("attribute", 0x21))!;

  assert.equal(attribute.fixedArguments.length, 5);
  assert.equal(attribute.namedArguments.length, 1);
  assert.equal(attribute.namedArguments[0]?.name, "Enabled");
  assert.match([...warnings].join(" "), /member kind/);
});

void test("unreadable constructors and invalid constructor kinds warn once and remain cached", () => {
  const fixture = createNativeFormatAttributeFixture();
  fixture.bytes[fixture.handle("attribute", 0x21).offset + 1] = 0x11;
  const warnings = new Set<string>();
  const members = new NativeFormatMembers(new NativeFormatStore(new NativeFormatReader(fixture.bytes), warnings));

  assert.equal(members.attributes.read(fixture.handle("attribute", 0x21)), null);
  assert.equal(members.attributes.read(fixture.handle("attribute", 0x21)), null);
  assert.match([...warnings].join(" "), /constructor/);
  assert.equal(members.attributes.read({ type: 0x21, offset: fixture.bytes.length }), null);
  assert.match([...warnings].join(" "), /outside/);
});
void test("invalid attribute handles and absent attribute fields remain harmless and visible", () => {
  const fixture = createNativeFormatAttributeFixture();
  const warnings = new Set<string>();
  const store = new NativeFormatStore(new NativeFormatReader(fixture.bytes), warnings);
  const members = new NativeFormatMembers(store);

  assert.equal(members.attributes.read({ type: 0x21, offset: 0 }), null);
  assert.equal(members.attributes.read(fixture.handle("attribute", 0x02)), null);
  assert.deepEqual(members.attributes.of(store.record(fixture.handle("null", 0x14))), []);
  assert.equal(members.attributes.read(fixture.handle("attribute", 0x21))?.fixedArguments.length, 5);
  assert.match([...warnings].join(" "), /Invalid.*handle/);
});

void test("truncated attribute tails preserve readable constructors and complete argument prefixes", () => {
  // A valid member-reference record followed by a constructor-only attribute at EOF.
  const fixture = createNativeFormatAttributeFixture();
  const offset = fixture.bytes.length;
  const token = fixture.handle("member", 0x27).offset * 128 + 0x27;
  const bytes = Uint8Array.from([...fixture.bytes, 15, token & 255,
    token >>> 8 & 255, token >>> 16 & 255, token >>> 24]);
  const warnings = new Set<string>();
  const members = new NativeFormatMembers(new NativeFormatStore(new NativeFormatReader(bytes), warnings));

  assert.deepEqual(members.attributes.read({ type: 0x21, offset }),
    { type: "ExampleAttribute", constructorName: ".ctor", fixedArguments: [], namedArguments: [] });
  assert.match([...warnings].join(" "), /outside/);
});

void test("unexpected dependency failures become attribute warnings", context => {
  const fixture = createNativeFormatAttributeFixture();
  const warnings = new Set<string>();
  const store = new NativeFormatStore(new NativeFormatReader(fixture.bytes), warnings);
  const members = new NativeFormatMembers(store);
  context.mock.method(store, "record", () => { throw "unreadable"; });

  assert.equal(members.attributes.read(fixture.handle("attribute", 0x21)), null);
  assert.match([...warnings].join(" "), /Attribute decoding failed/);
});
