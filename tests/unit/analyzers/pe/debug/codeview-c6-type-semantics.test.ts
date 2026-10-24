import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewC6Types } from "../../../../../analyzers/pe/debug/codeview-c6-type-records.js";
import { c6Type, c6Index, c6Name } from "../../../../fixtures/pe-codeview-c6.js";
import { legacyReader } from "../../../../fixtures/pe-legacy-codeview.js";
import { createPeWithC6Layouts } from "../../../../fixtures/pe-codeview-c6-layouts.js";
import { parsePeHeaders } from "../../../../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";

void test("C6 layout metadata survives PE debug-directory parsing", async () => {
  const file = createPeWithC6Layouts();
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const data = debug.entries[0]?.legacyCodeView?.directories[0]?.subsections[2]?.data;
  assert.ok(data?.kind === "types");
  assert.equal(data.encoding, "c6");
  assert.equal(data.records[2]?.name, "<Array>&amp;");
  assert.deepEqual(data.records[3]?.c6, { kind: "structure", bitLength: "32", fieldCount: "1",
    typeList: 514, nameList: 515, packing: 104 });
  assert.deepEqual(data.records[4]?.c6, { kind: "scalar", bitLength: "64",
    base: { kind: "style", value: "125" }, range: { base: { kind: "style", value: "125" },
      lower: "-9223372036854775808", upper: "18446744073709551615" } });
  assert.equal(debug.warning, null);
});

// C6 uses sizes in bits and OLF_INDEX-prefixed type references, unlike C7.
// Microsoft C Developer's Toolkit, 1.4 and 1.5.
// https://www.pcjs.org/documents/books/mspl13/c/ctoolkit/
void test("C6 retains array, structure and scalar sizes with their stored relationships", async () => {
  const warnings: string[] = [];
  const parsed = await readCodeViewC6Types(legacyReader([
    ...c6Type(120, [64, ...c6Index(512), ...c6Index(513), ...c6Name("Array")]),
    ...c6Type(121, [32, 1, ...c6Index(514), ...c6Index(515), ...c6Name("Struct"), 104]),
    ...c6Type(123, [16, 125, ...c6Name("Scalar"), 125, 0, 10])
  ], warnings));

  assert.deepEqual(parsed.records.map(value => value.c6), [
    { kind: "array", bitLength: "64", elementType: 512, indexType: 513 },
    { kind: "structure", bitLength: "32", fieldCount: "1", typeList: 514, nameList: 515, packing: 104 },
    { kind: "scalar", bitLength: "16", base: { kind: "style", value: "125" },
      range: { base: { kind: "style", value: "125" }, lower: "0", upper: "10" } }
  ]);
  assert.deepEqual(parsed.records.map(value => value.name), ["Array", "Struct", "Scalar"]);
  assert.deepEqual(warnings, []);
});

void test("C6 bitfield, pointer and procedure fields retain their distinct leaf encodings", async () => {
  const warnings: string[] = [];
  const parsed = await readCodeViewC6Types(legacyReader([
    ...c6Type(92, [5, 124, 17]),
    ...c6Type(122, [...c6Index(600), ...c6Name("IntelPointer")]),
    ...c6Type(122, [115, ...c6Index(601), ...c6Name("FarPointer")]),
    ...c6Type(117, [128, ...c6Index(602), 149, 3, ...c6Index(603)]),
    ...c6Type(117, [128, 129, 116, 0, ...c6Index(604)])
  ], warnings));

  assert.deepEqual(parsed.records.map(value => value.c6), [
    { kind: "bitfield", bitLength: "5", style: 124, position: 17 },
    { kind: "pointer", typeIndex: 600 }, { kind: "pointer", typeIndex: 601, style: 115 },
    { kind: "procedure", returnType: 602, callingConvention: 149, parameterCount: "3", argumentsType: 603 },
    { kind: "procedure", returnLeaf: 129, callingConvention: 116, parameterCount: "0", argumentsType: 604 }
  ]);
  assert.deepEqual(warnings, []);
});

void test("C6 exact sizes and bounds survive unsigned and signed 64-bit numeric encodings", async () => {
  const warnings: string[] = [];
  const parsed = await readCodeViewC6Types(legacyReader([
    ...c6Type(120, [135, 255, 255, 255, 255, 255, 255, 255, 255, ...c6Index()]),
    ...c6Type(123, [64, ...c6Index(700), ...c6Name("Range"), ...c6Index(701),
      139, 0, 0, 0, 0, 0, 0, 0, 128, 135, 255, 255, 255, 255, 255, 255, 255, 255])
  ], warnings));

  assert.deepEqual(parsed.records[0]?.c6, { kind: "array", bitLength: "18446744073709551615", elementType: 512 });
  assert.deepEqual(parsed.records[1]?.c6, { kind: "scalar", bitLength: "64", base: { kind: "type", index: 700 },
    range: { base: { kind: "type", index: 701 }, lower: "-9223372036854775808", upper: "18446744073709551615" } });
  assert.deepEqual(warnings, []);
});

void test("C6 known semantic prefixes survive a truncated name or subsequent bounds", async () => {
  const warnings: string[] = [];
  const parsed = await readCodeViewC6Types(legacyReader([
    ...c6Type(120, [16, ...c6Index(512), 130, 10, 65]),
    ...c6Type(123, [8, 125, ...c6Name("Partial"), 125, 136]),
    ...c6Type(121, [16, 1, ...c6Index(513), 131, 0]),
    ...c6Type(92, [8, 125])
  ], warnings));

  assert.deepEqual(parsed.records.map(value => value.c6), [
    { kind: "array", bitLength: "16", elementType: 512 },
    { kind: "scalar", bitLength: "8", base: { kind: "style", value: "125" } },
    { kind: "structure", bitLength: "16", fieldCount: "1", typeList: 513 }, undefined
  ]);
  assert.equal(parsed.records[1]?.name, "Partial");
  assert.equal(warnings.length, 4);
});

void test("C6 unusual signedness, negative dimensions and reversed ranges remain visible", async () => {
  const warnings: string[] = [];
  const parsed = await readCodeViewC6Types(legacyReader([
    ...c6Type(92, [136, 255, 99, 3]),
    ...c6Type(123, [8, 126, ...c6Name("Backwards"), 125, 10, 0]),
    ...c6Type(117, [128, 129, 99, 136, 255, ...c6Index()])
  ], warnings));

  assert.deepEqual(parsed.records[0]?.c6, { kind: "bitfield", bitLength: "-1", style: 99, position: 3 });
  assert.equal(warnings.length, 4);
  assert.match(warnings.join(" "), /negative bit length/);
  assert.match(warnings.join(" "), /unknown signedness/);
  assert.match(warnings.join(" "), /lower bound exceeds/);
  assert.match(warnings.join(" "), /parameter count is negative/);
});

void test("C6 structure field counts retain all unsigned bits without allocating declared lists", async () => {
  const parsed = await readCodeViewC6Types(legacyReader(c6Type(121,
    [16, 135, 255, 255, 255, 255, 255, 255, 255, 255, ...c6Index(600), ...c6Index(601),
      ...c6Name("Wide"), 105])));

  assert.deepEqual(parsed.records[0]?.c6, { kind: "structure", bitLength: "16",
    fieldCount: "18446744073709551615", typeList: 600, nameList: 601, packing: 105 });
});

void test("C6 scalar style values retain exact unsigned encodings instead of losing numeric precision", async () => {
  const parsed = await readCodeViewC6Types(legacyReader(c6Type(123,
    [16, 135, 255, 255, 255, 255, 255, 255, 255, 255, ...c6Name("Unknown")])));

  assert.deepEqual(parsed.records[0]?.c6, { kind: "scalar", bitLength: "16",
    base: { kind: "style", value: "18446744073709551615" } });
});
