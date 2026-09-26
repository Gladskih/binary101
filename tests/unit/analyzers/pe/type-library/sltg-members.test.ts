import assert from "node:assert/strict";
import { test } from "node:test";
import { SltgReader } from "../../../../../analyzers/pe/type-library/sltg-reader.js";
import { readSltgMembers } from "../../../../../analyzers/pe/type-library/sltg-members.js";

const members = () => {
  const reader = new SltgReader(new Uint8Array(64), []);
  const tail = new SltgReader(new Uint8Array(54), reader.issues);
  const names = new SltgReader(new TextEncoder().encode("Name\0\0arg\0"), []);
  tail.view.setUint16(0, 1, true);
  tail.view.setUint16(10, 0xffff, true);
  reader.view.setUint8(0, 0x4c);
  reader.view.setUint16(2, 0xffff, true);
  reader.view.setUint16(12, 0xffff, true);
  reader.view.setUint8(17, 0x80);
  reader.view.setUint16(18, 25, true);
  return { reader, tail, names };
};

void test("SLTG functions expose flags, numeric id, indirect return and parameter types", () => {
  const { reader, tail, names } = members();
  reader.view.setUint8(0, 0x6c);
  reader.view.setUint8(17, 0);
  reader.view.setUint16(18, 30, true);
  reader.view.setUint16(30, 25, true);
  reader.view.setUint16(22, 3, true);
  reader.view.setUint16(14, 24, true);
  reader.view.setUint8(16, 1 << 3);
  reader.view.setUint16(24, 6, true);
  reader.view.setUint16(26, 32, true);
  reader.view.setUint16(32, 3, true);
  const result = readSltgMembers(reader, names, tail);
  assert.equal(result.functions[0]?.type, "HRESULT");
  assert.equal(result.functions[0]?.flags, 3);
  assert.equal(result.functions[0]?.parameters[0]?.name, "arg");
  assert.equal(result.functions[0]?.parameters[0]?.type, "long");
});

for (const magic of [0, 0xcb, 0x8b]) {
  void test(`SLTG function validates magic or recognizes kind ${magic}`, () => {
    const { reader, tail, names } = members();
    reader.view.setUint8(0, magic);
    assert.doesNotThrow(() => readSltgMembers(reader, names, tail));
  });
}

void test("SLTG member chain detects premature termination and cycles", () => {
  const { reader, tail, names } = members();
  tail.view.setUint16(0, 2, true);
  assert.equal(readSltgMembers(reader, names, tail).functions.length, 1);
  reader.view.setUint16(2, 0, true);
  assert.equal(readSltgMembers(reader, names, tail).functions.length, 1);
  assert.match(reader.issues.join(), /cycle/);
});

const variables = () => {
  const fixture = members();
  fixture.tail.view.setUint16(0, 0, true);
  fixture.tail.view.setUint16(2, 1, true);
  fixture.tail.view.setUint16(10, 0, true);
  fixture.reader.view.setUint8(0, 0x0a);
  fixture.reader.view.setUint8(1, 2);
  fixture.reader.view.setUint16(8, 3, true);
  fixture.reader.view.setUint16(16, 0xffff, true);
  return fixture;
};

void test("SLTG variable records expose per-instance offsets, readonly and VARFLAGS", () => {
  const { reader, tail, names } = variables();
  reader.view.setUint8(0, 0x2a);
  reader.view.setUint8(1, 0x82);
  reader.view.setUint16(6, 8, true);
  reader.view.setUint16(18, 4, true);
  assert.equal(readSltgMembers(reader, names, tail).variables[0]?.instanceOffset, 8);
  assert.equal(readSltgMembers(reader, names, tail).variables[0]?.flags, 5);
});

for (const flags of [0x1a, 0x12, 0x42, 0]) {
  void test(`SLTG variables decode dispatch, constants and indirect types (${flags})`, () => {
    const { reader, tail, names } = variables();
    reader.view.setUint8(1, flags);
    assert.doesNotThrow(() => readSltgMembers(reader, names, tail));
  });
}

void test("SLTG string constants decode byte length and ANSI payload", () => {
  const { reader, tail, names } = variables();
  reader.view.setUint8(1, 0x12);
  reader.view.setUint16(8, 8, true);
  reader.view.setUint16(6, 24, true);
  reader.view.setUint16(24, 2, true);
  reader.data.set(new TextEncoder().encode("ok"), 26);
  assert.deepEqual(readSltgMembers(reader, names, tail).variables[0]?.value, { type: 8, value: "ok" });
});

void test("SLTG constants warn when their representation is unsupported", () => {
  const { reader, tail, names } = variables();
  reader.view.setUint8(1, 0x12);
  reader.view.setUint16(8, 5, true);
  assert.equal(readSltgMembers(reader, names, tail).variables[0]?.value, null);
  assert.match(reader.issues.join(), /unsupported/);
});

void test("SLTG variables validate magic and reuse the previous name sentinel", () => {
  const { reader, tail, names } = variables();
  reader.view.setUint8(0, 0);
  assert.deepEqual(readSltgMembers(reader, names, tail).variables, []);
  reader.view.setUint8(0, 0x0a);
  reader.view.setUint16(4, 0xfffe, true);
  assert.equal(readSltgMembers(reader, names, tail).variables[0]?.name, null);
});
