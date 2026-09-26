import assert from "node:assert/strict";
import { test } from "node:test";
import { SltgReader } from "../../../../../analyzers/pe/type-library/sltg-reader.js";
import { readSltgReferences, readSltgInterfaces } from "../../../../../analyzers/pe/type-library/sltg-references.js";
import type { TypeLibraryAnalysis } from "../../../../../analyzers/pe/type-library/types.js";

const referenceReader = (text: string): SltgReader => {
  const bytes = new TextEncoder().encode(text);
  const data = new Uint8Array(87 + 2 + bytes.length);
  const view = new DataView(data.buffer);
  data[0] = 0xdf;
  view.setUint32(68, 8, true);
  view.setUint16(87, bytes.length, true);
  data.set(bytes, 89);
  return new SltgReader(data, []);
};

const analysis = (): TypeLibraryAnalysis => ({ name: null, guid: null, documentation: null,
  helpFile: null, helpStringDll: null, helpContext: 0, helpStringContext: null,
  customData: [], types: [], imports: [], importedTypes: [] });

void test("SLTG resolves internal types by reference index", () => {
  const reader = referenceReader("*\\Rffff*#2");
  assert.deepEqual([...readSltgReferences(reader, reader, 0, analysis())], [[0, 200]]);
});

void test("SLTG extracts imported library identity and reuses imported references", () => {
  const reader = referenceReader("*\\R0*#4");
  const names = new SltgReader(new TextEncoder().encode(
    "*\\G{12345678-1234-1234-1234-123456789abc}#1.2#409#file.tlb#\0"), []);
  const library = analysis();
  assert.equal(readSltgReferences(reader, names, 0, library).get(0), 1);
  assert.equal(readSltgReferences(reader, names, 0, library).get(0), 1);
  assert.equal(library.imports.length, 1);
  assert.deepEqual(library.imports[0], { offset: 0, name: "file.tlb",
    guid: "12345678-1234-1234-1234-123456789abc", lcid: 1033, version: 0x20001 });
  assert.equal(library.importedTypes.length, 1);
});

void test("SLTG reports malformed import library strings", () => {
  const reader = referenceReader("*\\R0*#4");
  const names = new SltgReader(new TextEncoder().encode("bad\0"), []);
  assert.equal(readSltgReferences(reader, names, 0, analysis()).get(0), 1);
  assert.match(names.issues.join(), /library string is invalid/);
});

for (const text of ["bad", ""]) {
  void test(`SLTG rejects malformed reference strings (${text})`, () => {
    const reader = referenceReader(text);
    assert.equal(readSltgReferences(reader, reader, 0, analysis()).size, 0);
    assert.match(reader.issues.join(), /reference string/);
  });
}

void test("SLTG accepts the absent reference table sentinel", () => {
  const reader = referenceReader("*\\Rffff*#2");
  assert.equal(readSltgReferences(reader, reader, 0xffffffff, analysis()).size, 0);
});

for (const [offset, value] of [[0, 0], [68, 1], [68, 0xffffffff], [87, 0xffff]] as const) {
  void test(`SLTG rejects reference table corruption at ${offset}`, () => {
    const reader = referenceReader("*\\Rffff*#2");
    reader.view.setUint32(offset, value, true);
    assert.equal(readSltgReferences(reader, reader, 0, analysis()).size, 0);
    assert.ok(reader.issues.length);
  });
}

void test("SLTG interfaces carry implementation flags and detect cycles", () => {
  const reader = new SltgReader(new Uint8Array(22), []);
  reader.view.setUint16(0, 0x004a, true);
  reader.view.setUint8(6, 3);
  reader.references.set(0, 100);
  assert.deepEqual(readSltgInterfaces(reader, 0, 2), [{ reference: 100, flags: 3, customData: [] }]);
  assert.match(reader.issues.join(), /cyclic/);
});

void test("SLTG reports missing interface references and truncated implementation records", () => {
  const reader = new SltgReader(new Uint8Array(22), []);
  reader.view.setUint16(0, 0x004a, true);
  assert.equal(readSltgInterfaces(reader, 0, 1)[0]?.reference, -1);
  assert.deepEqual(readSltgInterfaces(reader, 1, 1), []);
  assert.ok(reader.issues.length);
});

for (const text of ["*\\Rffffffffffffffff*#1", "*\\Rffff*#ffffffffffffffff"]) {
  void test("SLTG refuses overflowing numeric references", () => {
    const reader = referenceReader(text);
    assert.equal(readSltgReferences(reader, reader, 0, analysis()).size, 0);
    assert.match(reader.issues.join(), /type index is invalid/);
  });
}

for (const suffix of ["65536.1#409", "1.65536#409", "1.1#ffffffffffffffff"]) {
  void test(`SLTG validates imported version and LCID ranges ${suffix}`, () => {
    const reader = referenceReader("*\\R0*#4");
    const names = new SltgReader(new TextEncoder().encode(
      `*\\G{12345678-1234-1234-1234-123456789abc}#${suffix}#file.tlb#\0`), []);
    const library = analysis();
    readSltgReferences(reader, names, 0, library);
    assert.deepEqual(library.imports, []);
    assert.match(names.issues.join(), /version or locale is invalid/);
  });
}
