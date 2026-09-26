import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSltgLibrary } from "../../../../../analyzers/pe/type-library/sltg.js";
import { createSltgLibrary } from "../../../../fixtures/type-library-sltg.js";

void test("SLTG parses library, type metadata, function signatures and parameters", () => {
  const issues: string[] = [];
  const result = parseSltgLibrary(createSltgLibrary(), issues);
  assert.deepEqual(issues, []);
  assert.equal(result.analysis?.name, "Lib");
  assert.equal(result.analysis?.types[0]?.name, "ITest");
  assert.equal(result.analysis?.types[0]?.version, 1);
  assert.equal(result.analysis?.types[0]?.size, 4);
  assert.equal(result.analysis?.types[0]?.functions[0]?.type, "HRESULT");
  assert.equal(result.analysis?.types[0]?.functions[0]?.callingConvention, 4);
  assert.deepEqual(result.analysis?.types[0]?.functions[0]?.parameters, [
    { name: "arg", type: "long", flags: 17, defaultValue: null, customData: [] }
  ]);
});

for (const offset of [4, 10, 42, 85, 95, 124, 160, 324, 334, 362]) {
  void test(`SLTG tolerates malformed fields at ${offset}`, () => {
    const data = createSltgLibrary();
    new DataView(data.buffer).setUint32(offset, 0xffffffff, true);
    const issues: string[] = [];
    assert.doesNotThrow(() => parseSltgLibrary(data, issues));
    assert.ok(issues.length);
  });
}

void test("SLTG reports an unknown name table marker", () => {
  const data = createSltgLibrary();
  new DataView(data.buffer).setUint16(414, 0x1234, true);
  const issues: string[] = [];
  parseSltgLibrary(data, issues);
  assert.match(issues.join(), /marker is invalid/);
});

void test("SLTG decodes simple aliases from the tail", () => {
  const data = createSltgLibrary();
  const view = new DataView(data.buffer);
  view.setUint8(114, 6);
  view.setUint16(180, 25, true);
  view.setUint16(188, 1, true);
  assert.equal(parseSltgLibrary(data, []).analysis?.types[0]?.alias, "HRESULT");
});

void test("SLTG decodes indirect aliases and dual interface flags", () => {
  const data = createSltgLibrary();
  const view = new DataView(data.buffer);
  view.setUint8(114, 6);
  view.setUint16(180, 18, true);
  assert.equal(parseSltgLibrary(data, []).analysis?.types[0]?.alias, "HRESULT");
  view.setUint8(111, 2);
  view.setUint8(112, 2);
  assert.equal(parseSltgLibrary(data, []).analysis?.types[0]?.kind, 4);
});

void test("SLTG name tables can include the documented extended prefix", () => {
  const data = createSltgLibrary();
  data.copyWithin(982, 950, 964);
  new DataView(data.buffer).setUint16(414, 0x200, true);
  assert.equal(parseSltgLibrary(data, []).analysis?.name, "Lib");
});

void test("SLTG bounds-checks type member headers separately from their containing block", () => {
  const data = createSltgLibrary();
  new DataView(data.buffer).setUint32(95, 128, true);
  const issues: string[] = [];
  assert.deepEqual(parseSltgLibrary(data, issues).analysis?.types, []);
  assert.match(issues.join(), /outside its block/);
});

void test("SLTG cross-checks its type count against blocks and metadata", () => {
  const data = createSltgLibrary();
  new DataView(data.buffer).setUint16(324, 0, true);
  const issues: string[] = [];
  parseSltgLibrary(data, issues);
  assert.match(issues.join(), /disagrees/);
});

for (const size of [0, 4, 35, 84, 86, 120, 213, 215, 540, 1013]) {
  void test(`SLTG tolerates truncation to ${size} bytes`, () => {
    const issues: string[] = [];
    assert.doesNotThrow(() => parseSltgLibrary(createSltgLibrary().subarray(0, size), issues));
    assert.ok(issues.length);
  });
}
