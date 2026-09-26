import assert from "node:assert/strict";
import { test } from "node:test";
import { readCustomData, readValue } from "../../../../../analyzers/pe/type-library/values.js";
import { createLibraryReader } from "../../../../fixtures/type-library.js";

// Wine MSFT_ReadValue reads small numerics in four-byte storage and wide numerics in eight.
for (const [type, expected] of [[0, null], [1, null], [24, null], [2, 42], [3, 42],
  [10, 42], [22, 42], [25, 42], [16, 42], [17, 42], [18, 42], [19, 42], [23, 42],
  [20, "42"], [21, "42"], [64, "42"], [6, "42 / 10000"], [11, "true"]] as const) {
  void test(`decodes stored variant type ${type}`, () => {
    const reader = createLibraryReader("CustData", 10);
    reader.view.setUint16(0, type, true);
    reader.view.setUint32(2, 42, true);
    assert.deepEqual(readValue(reader, 0), { type, value: expected });
    assert.deepEqual(readValue(reader, 0), { type, value: expected });
  });
}

for (const [type, size] of [[4, 4], [5, 8], [7, 8]] as const) {
  void test(`decodes floating variant ${type}`, () => {
    const reader = createLibraryReader("CustData", 10);
    reader.view.setUint16(0, type, true);
    writeFloat(reader.view, size);
    assert.deepEqual(readValue(reader, 0), { type, value: 1.5 });
  });
}

const writeFloat = (view: DataView, size: number): void => {
  if (size === 4) view.setFloat32(2, 1.5, true);
  else view.setFloat64(2, 1.5, true);
};

void test("inline variant decodes the type and packed value", () => {
  assert.deepEqual(readValue(createLibraryReader("CustData"), -1946157014), { type: 3, value: 42 });
});

// WMSFT_encode_variant masks I1/BOOL to 8 bits and I2 to 16 bits.
// https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.c
for (const [bits, type, value] of [[0xc00000ff, 16, -1], [0x8800ffff, 2, -1],
  [0xac0000ff, 11, "true"], [0xac000000, 11, "false"]] as const) {
  void test(`inline variant ${type} respects signedness and boolean semantics`, () => {
    assert.deepEqual(readValue(createLibraryReader("CustData"), bits | 0), { type, value });
  });
}

void test("BOOL zero is false", () => {
  const reader = createLibraryReader("CustData", 6);
  reader.view.setUint16(0, 11, true);
  assert.deepEqual(readValue(reader, 0), { type: 11, value: "false" });
});

void test("BSTR decoding bounds-checks lengths and the null sentinel", () => {
  const reader = createLibraryReader("CustData", 8);
  reader.view.setUint16(0, 8, true);
  reader.view.setInt32(2, 2, true);
  reader.data.set(new TextEncoder().encode("ok"), 6);
  assert.deepEqual(readValue(reader, 0), { type: 8, value: "ok" });
});

for (const length of [-1, -2, 10]) {
  void test(`BSTR handles null or invalid length ${length}`, () => {
    const reader = createLibraryReader("CustData", 6);
    reader.view.setUint16(0, 8, true);
    reader.view.setInt32(2, length, true);
    assert.deepEqual(readValue(reader, 0), { type: 8, value: null });
  });
}

void test("null BSTR values are valid rather than malformed payloads", () => {
  const reader = createLibraryReader("CustData", 6);
  reader.view.setUint16(0, 8, true);
  reader.view.setInt32(2, -1, true);
  assert.deepEqual(readValue(reader, 0), { type: 8, value: null });
  assert.deepEqual(reader.issues, []);
});

void test("variant decoding reuses the first parsed value", () => {
  const reader = createLibraryReader("CustData", 6);
  reader.view.setUint16(0, 3, true);
  reader.view.setInt32(2, 42, true);
  const value = readValue(reader, 0);
  reader.view.setInt32(2, 99, true);
  assert.equal(readValue(reader, 0), value);
  assert.equal(readValue(reader, 0)?.value, 42);
});

void test("custom data follows successive records until the explicit sentinel", () => {
  const reader = createLibraryReader("CDGuids", 24);
  reader.guids.set(0, "guid");
  reader.view.setInt32(4, -1946157014, true);
  reader.view.setInt32(8, 12, true);
  reader.view.setInt32(16, -1946157013, true);
  reader.view.setInt32(20, -1, true);
  assert.deepEqual(readCustomData(reader, 0).map(entry => entry.value?.value), [42, 43]);
  assert.deepEqual(reader.issues, []);
});

for (const [type, size] of [[3, 2], [8, 2], [20, 6], [99, 6]] as const) {
  void test(`value reports missing payload or unsupported type ${type}`, () => {
    const reader = createLibraryReader("CustData", size);
    reader.view.setUint16(0, type, true);
    assert.deepEqual(readValue(reader, 0), { type, value: null });
    assert.ok(reader.issues.length);
  });
}

void test("custom data resolves its GUID and rejects cyclic linked lists", () => {
  const reader = createLibraryReader("CDGuids", 12);
  reader.guids.set(0, "id");
  reader.view.setInt32(4, -1946157014, true);
  assert.deepEqual(readCustomData(reader, 0), [{ guid: "id", value: { type: 3, value: 42 } }]);
  assert.match(reader.issues.join(), /cycle/);
  assert.equal(readCustomData(reader, 0), readCustomData(reader, 0));
  assert.deepEqual(readCustomData(reader, -1), []);
  assert.deepEqual(readCustomData(reader, 12), []);
});

void test("value offsets outside their segment are rejected", () => {
  const reader = createLibraryReader("CustData", 12);
  assert.equal(readValue(reader, 128), null);
});
