import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMsftAnalysis } from "../../../../../analyzers/pe/type-library/msft.js";
import { createMsftLibrary } from "../../../../fixtures/type-library.js";
import { addTypeLibraryPreview } from "../../../../../analyzers/pe/resources/preview/type-library.js";

void test("deep MSFT parsing retains an empty, valid library", () => {
  // Wine MSFT_Header: 0x54 bytes; 15 directory records of 16 bytes.
  // https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.h
  const data = new Uint8Array(0x54);
  const view = new DataView(data.buffer);
  for (const offset of [8, 36, 56, 60, 64]) view.setInt32(offset, -1, true);
  const issues: string[] = [];
  const result = parseMsftAnalysis(data, [], issues);
  assert.equal(result.name, null);
  assert.deepEqual(result.types, []);
  assert.deepEqual(result.imports, []);
  assert.deepEqual(issues, []);
});

void test("MSFT resolves contracts, signatures, defaults, constants and imported references", () => {
  const result = addTypeLibraryPreview(createMsftLibrary(), "TYPELIB", null);
  const library = result?.preview?.typeLibrary?.analysis;
  assert.equal(result?.issues, undefined);
  assert.equal(library?.name, "Lib");
  assert.equal(library?.documentation, "Example");
  assert.deepEqual(library?.customData[0]?.value, { type: 3, value: -123 });
  assert.equal(library?.imports[0]?.name, "a.tlb");
  assert.equal(library?.imports[0]?.version, 0x20001);
  assert.equal(library?.importedTypes[0]?.identifier, "00000000-0000-0000-0000-000000000000");
  assert.equal(library?.types[0]?.alignment, 4);
  assert.equal(library?.types[0]?.functions[0]?.name, "Run");
  assert.equal(library?.types[0]?.functions[0]?.type, "long*");
  assert.equal(library?.types[0]?.functions[0]?.parameters[0]?.type, "href(1)");
  assert.deepEqual(library?.types[0]?.functions[0]?.parameters[0]?.defaultValue,
    { type: 3, value: 42 });
  assert.deepEqual(library?.types[0]?.variables[0]?.value, { type: 3, value: -123 });
  assert.equal(library?.types[1]?.alias, "HRESULT");
  assert.equal(library?.types[2]?.dll, "Example");
  assert.deepEqual(library?.types[3]?.interfaces, [{ reference: 0, flags: 3, customData: [] }]);
});

void test("MSFT deep parser tolerates a truncated header", () => {
  const issues: string[] = [];
  assert.deepEqual(parseMsftAnalysis(new Uint8Array(), [], issues).types, []);
  assert.match(issues.join(), /header is truncated/);
});

for (const offset of [0, 8, 20, 32, 84, 100, 512, 536, 588, 896, 1520, 1532, 1800, 1804, 1888]) {
  void test(`MSFT validates adversarial fields at ${offset}`, () => {
    const data = createMsftLibrary();
    new DataView(data.buffer).setUint32(offset, 0xffffffff, true);
    assert.doesNotThrow(() => addTypeLibraryPreview(data, "TYPELIB", null));
  });
}

void test("MSFT reports cycles in implemented interface lists", () => {
  const data = createMsftLibrary();
  const view = new DataView(data.buffer);
  view.setUint16(888, 2, true);
  view.setInt32(1532, 0, true);
  assert.match(addTypeLibraryPreview(data, "TYPELIB", null)?.issues?.join() ?? "", /cycle/);
});

void test("MSFT excessive member counts do not suppress independent valid interfaces", () => {
  const data = createMsftLibrary();
  const view = new DataView(data.buffer);
  // Fixture type bases are contiguous 100-byte MSFT_TypeInfoBase records at offset 512.
  view.setUint16(536, 65535, true);
  view.setUint16(538, 0, true);
  view.setUint16(636, 34460, true);
  const result = addTypeLibraryPreview(data, "TYPELIB", null);
  assert.deepEqual(result?.preview?.typeLibrary?.analysis?.types[3]?.interfaces,
    [{ reference: 0, flags: 3, customData: [] }]);
  assert.match(result?.issues?.join() ?? "", /index tables.*truncated/);
});

void test("MSFT validates its typeinfo offset table", () => {
  const data = createMsftLibrary();
  new DataView(data.buffer).setUint32(84, 1, true);
  assert.match(addTypeLibraryPreview(data, "TYPELIB", null)?.issues?.join() ?? "", /disagrees/);
});

void test("MSFT resolves the optional help-string DLL and library help contexts", () => {
  const data = createMsftLibrary();
  data.copyWithin(88, 84, 340);
  const view = new DataView(data.buffer);
  view.setUint32(20, 0x101, true);
  view.setInt32(84, 0, true);
  view.setUint32(40, 123, true);
  view.setUint32(44, 456, true);
  const result = addTypeLibraryPreview(data, "TYPELIB", null);
  assert.equal(result?.issues, undefined);
  assert.equal(result?.preview?.typeLibrary?.analysis?.helpStringDll, "Example");
  assert.equal(result?.preview?.typeLibrary?.analysis?.helpStringContext, 123);
  assert.equal(result?.preview?.typeLibrary?.analysis?.helpContext, 456);
});
