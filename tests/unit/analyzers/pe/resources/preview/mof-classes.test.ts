import assert from "node:assert/strict";
import { test } from "node:test";
import { parseBinaryMofClasses } from "../../../../../../analyzers/pe/resources/preview/mof-classes.js";
import { decodedMofFixture } from "../../../../../helpers/binary-mof-fixture.js";

const firstPartEnd = (bytes: Uint8Array): number => new DataView(bytes.buffer).getUint32(4, true);
const classStart = 20;
const qualifiersStart = classStart + 20;
const variableStart = (bytes: Uint8Array): number => qualifiersStart +
  new DataView(bytes.buffer).getUint32(classStart + 8, true);
const methodStart = (bytes: Uint8Array): number => qualifiersStart +
  new DataView(bytes.buffer).getUint32(classStart + 12, true);
const secondVariableStart = (bytes: Uint8Array): number => variableStart(bytes) + 8 +
  new DataView(bytes.buffer).getUint32(variableStart(bytes) + 8, true);
const changeWord = (offset: (bytes: Uint8Array) => number, value: number): Uint8Array => {
  const bytes = decodedMofFixture();
  new DataView(bytes.buffer).setUint32(offset(bytes), value, true);
  return bytes;
};
const parse = (bytes: Uint8Array): { classes: ReturnType<typeof parseBinaryMofClasses>;
  issues: string[] } => {
  const issues: string[] = [];
  return { classes: parseBinaryMofClasses(bytes, firstPartEnd(bytes), issues), issues };
};

void test("parses class identity, GUID, properties, and methods", () => {
  const bytes = decodedMofFixture();
  const issues: string[] = [];

  const classes = parseBinaryMofClasses(bytes, new DataView(bytes.buffer).getUint32(4, true), issues);

  assert.deepEqual(classes, [{ name: "TestClass", guid: "{12345678-1234-1234-1234-123456789abc}",
    namespace: null, superclass: null, properties: [{ name: "Payload", type: "UInt32" }],
    methods: ["Refresh"] }]);
  assert.deepEqual(issues, []);
});

void test("rejects a truncated class root", () => {
  const issues: string[] = [];
  assert.deepEqual(parseBinaryMofClasses(new Uint8Array(10), 10, issues), []);
  assert.match(issues.join(" "), /truncated/);
});

void test("rejects fractional and out-of-range class section bounds", () => {
  const bytes = decodedMofFixture();
  for (const end of [20.5, Number.NaN, bytes.length + 1]) {
    const issues: string[] = [];
    assert.deepEqual(parseBinaryMofClasses(bytes, end, issues), []);
    assert.deepEqual(issues, ["Binary MOF class root is truncated."]);
  }
});

void test("rejects an unsupported class root version", () => {
  const bytes = decodedMofFixture();
  bytes[8] = 2;
  const issues: string[] = [];
  assert.deepEqual(parseBinaryMofClasses(bytes, bytes.length, issues), []);
  assert.match(issues.join(" "), /version/);
});

void test("reports a truncated class record", () => {
  const result = parse(changeWord(() => classStart, 0xffffffff));
  assert.deepEqual(result.classes, []);
  assert.match(result.issues.join(" "), /class records/);
});

void test("reports an invalid class header and unsupported instance", () => {
  const invalid = parse(changeWord(() => classStart + 4, 1));
  const instance = parse(changeWord(() => classStart + 16, 1));
  assert.deepEqual(invalid.classes, []);
  assert.match(invalid.issues.join(" "), /class header/);
  assert.deepEqual(instance.classes, []);
  assert.match(instance.issues.join(" "), /not supported/);
});

void test("reports invalid qualifier and class data sizes", () => {
  const inconsistent = parse(changeWord(() => qualifiersStart, 9));
  const oversized = parse(changeWord(() => classStart + 8, 0xffffffff));
  assert.match(inconsistent.issues.join(" "), /qualifier table/);
  assert.match(oversized.issues.join(" "), /class data/);
});

void test("reports malformed qualifier records", () => {
  const invalid = parse(changeWord(() => qualifiersStart + 8, 0xffffffff));
  const badName = parse(changeWord(() => qualifiersStart + 8 + 12, 0xffffffff));
  const tooMany = parse(changeWord(() => qualifiersStart + 4, 2));
  assert.match(invalid.issues.join(" "), /qualifier records/);
  assert.match(badName.issues.join(" "), /qualifier records/);
  assert.match(tooMany.issues.join(" "), /qualifier records/);
});

void test("reports malformed variable records and tables", () => {
  const badTable = parse(changeWord(variableStart, 0xffffffff));
  const badRecord = parse(changeWord(bytes => variableStart(bytes) + 8, 0xffffffff));
  const badName = parse(changeWord(bytes => secondVariableStart(bytes) + 12, 1));
  const tooMany = parse(changeWord(bytes => variableStart(bytes) + 4, 3));
  assert.match(badTable.issues.join(" "), /variable table/);
  assert.match(badRecord.issues.join(" "), /variable records/);
  assert.match(badName.issues.join(" "), /variable name/);
  assert.match(tooMany.issues.join(" "), /variable records/);
});

void test("reports malformed class property and method records", () => {
  const badProperty = parse(changeWord(bytes => variableStart(bytes) + 8 + 8, 1));
  const badMethodTable = parse(changeWord(methodStart, 0xffffffff));
  const badMethod = parse(changeWord(bytes => methodStart(bytes) + 8, 0xffffffff));
  const tooManyMethods = parse(changeWord(bytes => methodStart(bytes) + 4, 2));
  assert.match(badProperty.issues.join(" "), /class property/);
  assert.match(badMethodTable.issues.join(" "), /method table/);
  assert.match(badMethod.issues.join(" "), /method records/);
  assert.match(tooManyMethods.issues.join(" "), /method records/);
});

void test("reports invalid class property and variable strings", () => {
  const badPropertyString = parse(changeWord(bytes => variableStart(bytes) + 8 + 12,
    0xffffffff));
  const badVariableSize = parse(changeWord(bytes => secondVariableStart(bytes) + 16,
    0xfffffffe));
  assert.match(badPropertyString.issues.join(" "), /property string/);
  assert.match(badVariableSize.issues.join(" "), /variable name/);
});

void test("reports malformed method names and truncated method tables", () => {
  const badName = parse(changeWord(bytes => methodStart(bytes) + 8 + 12, 1));
  const source = decodedMofFixture();
  const truncated = source.slice(0, methodStart(source) + 4);
  new DataView(truncated.buffer).setUint32(4, truncated.length, true);
  new DataView(truncated.buffer).setUint32(classStart, truncated.length - classStart, true);
  const missing = parse(truncated);
  assert.match(badName.issues.join(" "), /method records/);
  assert.match(missing.issues.join(" "), /method table/);
});

void test("does not treat unrelated qualifiers as class GUIDs", () => {
  const bytes = decodedMofFixture();
  bytes.set(new TextEncoder().encode("x\0"), qualifiersStart + 8 + 16);
  const result = parse(bytes);
  assert.equal(result.classes[0]?.guid, null);
  assert.deepEqual(result.issues, []);
});

void test("accepts case-insensitive GUID qualifiers of string type", () => {
  const bytes = decodedMofFixture();
  const view = new DataView(bytes.buffer);
  const nameStart = qualifiersStart + 8 + 16;
  for (const [index, char] of [..."GUID"].entries()) {
    view.setUint16(nameStart + index * 2, char.charCodeAt(0), true);
  }
  const string = parse(bytes);
  const numeric = parse(changeWord(() => qualifiersStart + 8 + 4, 3));
  assert.equal(string.classes[0]?.guid, "{12345678-1234-1234-1234-123456789abc}");
  assert.equal(numeric.classes[0]?.guid, null);
  assert.deepEqual(string.issues, []);
  assert.deepEqual(numeric.issues, []);
});

void test("decodes supported MOF property types and array flags", () => {
  // bmfparse.c variable type codes and the 0x2000 array flag.
  const types: Array<[number, string]> = [
    [0x02, "SInt16"], [0x03, "SInt32"], [0x04, "Real32"], [0x05, "Real64"],
    [0x08, "String"], [0x0b, "Boolean"], [0x10, "SInt8"], [0x11, "UInt8"],
    [0x12, "UInt16"], [0x13, "UInt32"], [0x14, "SInt64"], [0x15, "UInt64"],
    [0x65, "Datetime"], [0x67, "Char16"], [0x0d, "Object"]
  ];
  for (const [code, expected] of types) {
    const scalar = parse(changeWord(bytes => secondVariableStart(bytes) + 4, code));
    const array = parse(changeWord(bytes => secondVariableStart(bytes) + 4, code | 0x2000));
    assert.equal(scalar.classes[0]?.properties[0]?.type, expected);
    assert.equal(array.classes[0]?.properties[0]?.type, `${expected}[]`);
    assert.deepEqual(scalar.issues, []);
    assert.deepEqual(array.issues, []);
  }
  const unknown = parse(changeWord(bytes => secondVariableStart(bytes) + 4, 0xfe));
  assert.equal(unknown.classes[0]?.properties[0]?.type, "Type 0xfe");
});

void test("reads namespace and superclass identity properties", () => {
  const namespace = parse(decodedMofFixture("__NAMESPACE"));
  const superclass = parse(decodedMofFixture("__SUPERCLASS"));
  const unknown = parse(decodedMofFixture("Unrecognized"));
  assert.equal(namespace.classes[0]?.namespace, "TestClass");
  assert.equal(superclass.classes[0]?.superclass, "TestClass");
  assert.equal(unknown.classes[0]?.name, null);
  assert.deepEqual(namespace.issues, []);
  assert.deepEqual(superclass.issues, []);
  assert.deepEqual(unknown.issues, []);
});

void test("survives every truncation point of a class section", () => {
  const fixture = decodedMofFixture();
  for (let length = 0; length < fixture.length; length += 1) {
    const issues: string[] = [];
    const bytes = fixture.subarray(0, length);
    assert.doesNotThrow(() => parseBinaryMofClasses(bytes,
      Math.min(firstPartEnd(fixture), length), issues));
  }
});
