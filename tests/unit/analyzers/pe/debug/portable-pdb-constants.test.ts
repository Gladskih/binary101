import assert from "node:assert/strict";
import { test } from "node:test";
import { decodePortablePdbConstant } from "../../../../../analyzers/pe/debug/portable-pdb-constants.js";

const counts = new Map([[0x01, 2], [0x02, 1], [0x1b, 1]]);
const decode = (bytes: number[]) => {
  const issues: string[] = [];
  return { value: decodePortablePdbConstant(Uint8Array.from(bytes), counts, issues), issues };
};

[
  { bytes: [2, 1], value: true }, { bytes: [2, 0], value: false },
  { bytes: [3, 65, 0], value: "A" }, { bytes: [4, 255], value: -1 },
  { bytes: [5, 255], value: 255 }, { bytes: [6, 255, 255], value: -1 },
  { bytes: [7, 255, 255], value: 65535 }, { bytes: [8, 255, 255, 255, 255], value: -1 },
  { bytes: [9, 255, 255, 255, 255], value: 4294967295 },
  { bytes: [10, 255, 255, 255, 255, 255, 255, 255, 255], value: "-1" },
  { bytes: [11, 255, 255, 255, 255, 255, 255, 255, 255], value: "18446744073709551615" },
  { bytes: [12, 0, 0, 128, 63], value: 1 },
  { bytes: [13, 0, 0, 0, 0, 0, 0, 240, 63], value: 1 },
  // Asymmetric values distinguish little-endian decoding from byte-swapped output.
  { bytes: [6, 52, 18], value: 0x1234 }, { bytes: [7, 120, 86], value: 0x5678 },
  { bytes: [8, 120, 86, 52, 18], value: 0x12345678 },
  { bytes: [9, 254, 220, 186, 152], value: 0x98badcfe },
  { bytes: [10, 42, 0, 0, 0, 0, 0, 0, 0], value: "42" },
  { bytes: [11, 43, 0, 0, 0, 0, 0, 0, 0], value: "43" },
  { bytes: [14, 65, 0, 0, 216], value: "A\ud800" },
  { bytes: [14, 255, 0], value: "\u00ff" },
  { bytes: [14, 255], value: null }, { bytes: [14], value: "" }, { bytes: [28], value: null }
].forEach(({ bytes, value }) => {
  void test(`Portable PDB constant decodes primitive type ${bytes[0]} as ${JSON.stringify(value)}`, () => {
    assert.deepEqual(decode(bytes), { value: { typeCode: bytes[0], value }, issues: [] });
  });
});

void test("Portable PDB constants preserve enum type references and custom modifiers", () => {
  // cmod_reqd TypeRef #1; cmod_opt TypeSpec #1; int32 enum value 3, TypeDef #1.
  assert.deepEqual(decode([31, 5, 32, 6, 8, 3, 0, 0, 0, 4]), { value: {
    typeCode: 8, value: 3, typeReference: { tableId: 2, row: 1 }, modifiers: [
      { required: true, typeReference: { tableId: 1, row: 1 } },
      { required: false, typeReference: { tableId: 0x1b, row: 1 } }
    ]
  }, issues: [] });
  assert.deepEqual(decode([11, 43, 0, 0, 0, 0, 0, 0, 0, 5]), { value: {
    typeCode: 11, value: "43", typeReference: { tableId: 1, row: 1 }
  }, issues: [] });
});

void test("Portable PDB constants preserve type-dependent payloads for CLR metadata resolution", () => {
  assert.deepEqual(decode([17, 5, 1, 2]), { value: { typeCode: 17,
    typeReference: { tableId: 1, row: 1 }, data: [1, 2] }, issues: [] });
  assert.deepEqual(decode([18, 5]), { value: { typeCode: 18,
    typeReference: { tableId: 1, row: 1 }, data: [] }, issues: [] });
});

[
  { bytes: [], reason: /truncated/ }, { bytes: [2], reason: /truncated/ },
  { bytes: [2, 2], reason: /neither zero nor one/ }, { bytes: [8, 0], reason: /truncated/ },
  { bytes: [14, 0], reason: /partial UTF-16/ }, { bytes: [17], reason: /compressed integer/ },
  { bytes: [31], reason: /compressed integer/ }, { bytes: [31, 5], reason: /truncated/ },
  { bytes: [28, 0], reason: /trailing/ },
  { bytes: [8, 0, 0, 0, 0, 7], reason: /type reference is out of range/ },
  { bytes: [8, 0, 0, 0, 0, 13], reason: /type reference is out of range/ },
  { bytes: [8, 0, 0, 0, 0, 0], reason: /type reference is out of range/ },
  { bytes: [255], reason: /unsupported constant type 255/ }
].forEach(({ bytes, reason }) => {
  void test(`Portable PDB constant diagnoses malformed signature ${bytes}`, () => {
    const { value, issues } = decode(bytes);

    assert.equal(value, null);
    assert.match(issues.join(" | "), reason);
  });
});

void test("Portable PDB constant handles absent blobs and rejects trailing enum data", () => {
  const issues: string[] = [];

  assert.equal(decodePortablePdbConstant(null, counts, issues), null);
  assert.deepEqual(issues, []);
  assert.equal(decode([8, 0, 0, 0, 0, 5, 0]).value, null);
  assert.equal(decode([12, 0, 0, 0, 0, 5]).value, null);
});
