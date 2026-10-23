import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewC6Types } from "../../../../../analyzers/pe/debug/codeview-c6-type-records.js";
import { c6Type, c6Index, c6Name } from "../../../../fixtures/pe-codeview-c6.js";
import { legacyReader, legacyU16, legacyPascal } from "../../../../fixtures/pe-legacy-codeview.js";

for (const [type, body, name] of [
  [93, [...c6Index(), ...c6Name("Alias")], "Alias"],
  [120, [16, ...c6Index(), ...c6Index(), ...c6Name("Array")], "Array"],
  [122, [116, ...c6Index(), ...c6Name("Pointer")], "Pointer"],
  [123, [8, 125, ...c6Name("Scalar")], "Scalar"],
  [121, [16, 1, ...c6Index(), ...c6Index(), ...c6Name("Structure"), 104], "Structure"],
  [121, [16, 0, 128, 128, ...c6Name("Union")], "Union"],
  [167, [0, 0, 0, ...legacyPascal("CobolRoot")], "CobolRoot"],
  [166, [...c6Index(), 0, 0, 0, ...legacyPascal("CobolRef")], "CobolRef"]
] as const) {
  void test(`C6 type ${type} preserves ${name}`, async () => {
    const warnings: string[] = [];
    const data = await readCodeViewC6Types(legacyReader(c6Type(type, body), warnings));

    assert.deepEqual(data, { kind: "types", encoding: "c6", records: [{ type, name }] });
    assert.deepEqual(warnings, []);
  });
}

void test("C6 lists preserve member names without scanning numeric payloads as text", async () => {
  const data = await readCodeViewC6Types(legacyReader(c6Type(127, [...c6Name("count"), 0,
    ...c6Name("ratio"), 133, 130, 0, ...c6Index()])));

  assert.deepEqual(data.records, [{ type: 127, strings: ["count", "ratio"] }]);
});

for (const [tag, body, strings] of [[0, c6Name("low"), ["low"]], [1, [0], []], [2, [0, 10], []],
  [3, [0, ...c6Name("high")], ["high"]], [4, [...c6Name("low"), 10], ["low"]],
  [5, [...c6Name("low"), ...c6Name("high")], ["low", "high"]], [6, [10], []],
  [7, c6Name("temp"), ["temp"]]] as const) {
  void test(`C6 FORTRAN array bounds tag ${tag} preserves its variable names`, async () => {
    const data = await readCodeViewC6Types(legacyReader(c6Type(142, [tag, ...body])));

    assert.deepEqual(data.records, [{ type: 142, strings: [...strings] }]);
  });
}

void test("C6 unknown and malformed leaves preserve neighboring records and valid prefixes", async () => {
  const warnings: string[] = [];
  const data = await readCodeViewC6Types(legacyReader([
    ...c6Type(255, c6Name("fake")), ...c6Type(93, [131, 0]), ...c6Type(93, [...c6Index(), 129]),
    ...c6Type(127, [...c6Name("good"), 255]), ...c6Type(142, [8]),
    ...c6Type(93, [...c6Index(), ...c6Name("Alias")])
  ], warnings));

  assert.deepEqual(data.records, [{ type: 255 }, { type: 93 }, { type: 93 },
    { type: 127, strings: ["good"] }, { type: 142, strings: [] }, { type: 93, name: "Alias" }]);
  assert.equal(warnings.length, 5);
});

for (const bytes of [[0], [0, 1], [0, 0, 0], [0, 2, 0, 93]]) {
  void test(`C6 type framing bounds ${bytes} produces warnings`, async () => {
    const warnings: string[] = [];
    assert.deepEqual((await readCodeViewC6Types(legacyReader(bytes, warnings))).records, []);
    assert.equal(warnings.length, 1);
  });
}

void test("C6 skip padding cannot introduce fake type strings", async () => {
  const warnings: string[] = [];
  const data = await readCodeViewC6Types(legacyReader([
    ...c6Type(144, [...legacyU16(1024), ...c6Name("not_a_name")]), ...c6Type(128)
  ], warnings));

  assert.deepEqual(data.records, [{ type: 144 }, { type: 128 }]);
  assert.deepEqual(warnings, []);
});

for (const [type, body] of [[92, [8, 125, 0]], [96, [16]], [114, [128, 116]],
  [118, c6Index()], [120, [8, ...c6Index()]], [122, c6Index()], [123, [8, 125]],
  [140, c6Index()], [141, [0, 16]], [141, [1, 0]],
  [117, [128, ...c6Index(), 99, 0, ...c6Index()]], [117, [128, 129, 99, 0, ...c6Index()]],
  [145, [...c6Index(), 146, 0, 0]], [145, [...c6Index(), 147, 0, 0, 0, 0]],
  [145, [...c6Index(), 128]], [145, [...c6Index(), 129]],
  [145, [...c6Index(), 131, 0, 0]]] as const) {
  void test(`C6 type ${type} validates its name-free body ${body}`, async () => {
    const warnings: string[] = [];
    const data = await readCodeViewC6Types(legacyReader(c6Type(type, body), warnings));

    assert.deepEqual(data.records, [{ type }]);
    assert.deepEqual(warnings, []);
  });
}

void test("C6 COBOL alphanumeric literal bytes remain readable after linkage and OCCURS fields", async () => {
  const warnings: string[] = [];
  const data = await readCodeViewC6Types(legacyReader(c6Type(167,
    [1, 0xc1, 1, 0xf0, 2, 10, 0x80, 4, 72, 101, 108, 108, 111]), warnings));

  assert.deepEqual(data.records, [{ type: 167, strings: ["Hello"] }]);
  assert.deepEqual(warnings, []);
});

void test("C6 variants preserve tag names and walk value and name/type lists within the record", async () => {
  const warnings: string[] = [];
  const data = await readCodeViewC6Types(legacyReader([
    ...c6Type(121, [8, 1, ...c6Index(), ...c6Index(), 105, 1, ...c6Index(), ...c6Name("tag"),
      2, 0, 1, ...c6Index(), ...c6Index()]),
    ...c6Type(121, [8, 0, 128, 128, 104, 1, 128, 128, 0, ...c6Index(), ...c6Index()]),
    ...c6Type(123, [8, ...c6Index(), ...c6Name("Range"), ...c6Index(), 136, 255, 10]),
    ...c6Type(123, [8, 125, ...c6Name("Number"), 125, 0, 10])
  ], warnings));

  assert.deepEqual(data.records, [{ type: 121, strings: ["tag"] }, { type: 121 },
    { type: 123, name: "Range" }, { type: 123, name: "Number" }]);
  assert.deepEqual(warnings, []);
});

for (const [code, bytes] of [[133, [0, 1]], [134, [0, 1, 0, 0]], [135, [0, 1, 0, 0, 0, 0, 0, 0]],
  [136, [255]], [137, [255, 255]], [138, [255, 255, 255, 255]],
  [139, [255, 255, 255, 255, 255, 255, 255, 255]]] as const) {
  void test(`C6 numeric width ${code} consumes the complete value`, async () => {
    const warnings: string[] = [];
    const data = await readCodeViewC6Types(legacyReader(c6Type(123,
      [code, ...bytes, 125, ...c6Name("Number")]), warnings));

    assert.equal(data.records[0]?.name, "Number");
    assert.deepEqual(warnings, []);
  });
}

for (const [type, body, message] of [
  [93, [128], /index leaf/], [121, [8, 136, 255], /Negative.*field/],
  [121, [8, 0, 128, 128, 255], /packing leaf/], [121, [8, 0, 128, 128, 104, 136, 255], /Negative.*tag/],
  [121, [8, 0, 128, 128, 104, 1, 128, 128, 136, 255], /Negative.*variant/],
  [145, [...c6Index(), 255], /pointer base/], [141, [2], /FORTRAN string tag/],
  [128, [0], /trailing bytes/], [144, [0], /bounds/], [96, [255], /numeric leaf/],
  [127, [133, 1], /bounds/], [167, [1, 0xc1, 0xd0], /variable-count/]
] as const) {
  void test(`C6 type ${type} reports malformed body ${body}`, async () => {
    const warnings: string[] = [];
    await readCodeViewC6Types(legacyReader(c6Type(type, body), warnings));

    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, message);
  });
}

for (const body of [[1, 0x20, 0], [1, 0, 0, 0], [1, 0xa0, 0], [1, 0x88, 0x80, 0],
  [1, 0x88, 0xc0, 0, 0, 0], [1, 0x88, 0xf0, 0, 0, 0], [1, 0xc0],
  [1, 0xe0, 0, 0x20, 0]]) {
  void test(`C6 COBOL non-literal and variable-size body ${body} does not invent strings`, async () => {
    const warnings: string[] = [];
    const data = await readCodeViewC6Types(legacyReader(c6Type(167, body), warnings));

    assert.deepEqual(data.records, [{ type: 167 }]);
    assert.deepEqual(warnings, []);
  });
}

void test("C6 empty type streams are valid", async () => {
  assert.deepEqual(await readCodeViewC6Types(legacyReader([])), { kind: "types", encoding: "c6", records: [] });
});

void test("C6 array names can follow an omitted index type", async () => {
  const warnings: string[] = [];
  const data = await readCodeViewC6Types(legacyReader(c6Type(120,
    [8, ...c6Index(), ...c6Name("Array")]), warnings));

  assert.deepEqual(data.records, [{ type: 120, name: "Array" }]);
  assert.deepEqual(warnings, []);
});

for (const [code, bytes] of [[133, [0, 128]], [135, [0, 0, 0, 0, 0, 0, 0, 128]],
  [136, [1]], [137, [1, 0]], [138, [1, 0, 0, 0]], [139, [1, 0, 0, 0, 0, 0, 0, 0]]] as const) {
  void test(`C6 field count ${code} preserves signedness without truncating unsigned values`, async () => {
    const warnings: string[] = [];
    const data = await readCodeViewC6Types(legacyReader(c6Type(121,
      [8, code, ...bytes, ...c6Index(), ...c6Index(), ...c6Name("Structure")]), warnings));

    assert.equal(data.records[0]?.name, "Structure");
    assert.deepEqual(warnings, []);
  });
}

void test("C6 multi-byte variant counts consume all variants rather than their low byte", async () => {
  const warnings: string[] = [];
  const variants = Array.from({ length: 257 }, () => [0, ...c6Index(), ...c6Index()]).flat();
  const data = await readCodeViewC6Types(legacyReader(c6Type(121,
    [8, 0, 128, 128, 104, 133, 1, 1, 128, 128, ...variants]), warnings));

  assert.deepEqual(data.records, [{ type: 121 }]);
  assert.deepEqual(warnings, []);
});

void test("C6 zero tags require no variant records", async () => {
  const warnings: string[] = [];
  await readCodeViewC6Types(legacyReader(c6Type(121, [8, 0, 128, 128, 104, 0, 128, 128]), warnings));
  assert.deepEqual(warnings, []);
});

void test("C6 invalid type lengths are diagnosed before retaining a record", async () => {
  const warnings: string[] = [];
  const data = await readCodeViewC6Types(legacyReader([...c6Type(128), 0, 20, 0, 93], warnings));
  assert.deepEqual(data.records, [{ type: 128 }]);
  assert.match(warnings[0]!, /Invalid C6 type record length/);
});

void test("C6 final type bounds are relative to the remaining stream after skip padding", async () => {
  const warnings: string[] = [];
  const data = await readCodeViewC6Types(legacyReader([
    ...c6Type(144, [0, 2, ...new Array<number>(64).fill(0)]), 0, 20, 0, 93
  ], warnings));
  assert.deepEqual(data.records, [{ type: 144 }]);
  assert.match(warnings[0]!, /Invalid C6 type record length/);
});

void test("C6 union variants omit the numeric case values present for structure variants", async () => {
  const warnings: string[] = [];
  await readCodeViewC6Types(legacyReader(c6Type(121,
    [8, 0, 128, 128, 104, 1, 128, 128, 1, ...c6Index(), ...c6Index()]), warnings));
  assert.deepEqual(warnings, []);
});

void test("C6 lists distinguish index and empty leaves from name and numeric bytes", async () => {
  const warnings: string[] = [];
  const data = await readCodeViewC6Types(legacyReader(c6Type(127,
    [128, 129, ...c6Index(), ...c6Name("member"), 133, 130, 0]), warnings));
  assert.deepEqual(data.records, [{ type: 127, strings: ["member"] }]);
  assert.deepEqual(warnings, []);
});

for (const [type, body, message] of [[93, [...c6Index(), 129], /Invalid C6 string leaf/],
  [96, [128], /Unknown C6 numeric leaf/], [255, [], /C6 type leaf 255 body is not decoded/],
  [142, [8], /array bounds tag 8/]] as const) {
  void test(`C6 diagnostics identify invalid type ${type} body ${body}`, async () => {
    const warnings: string[] = [];
    await readCodeViewC6Types(legacyReader(c6Type(type, body), warnings));
    assert.match(warnings[0]!, message);
  });
}

for (const tag of [1, 2, 6]) {
  void test(`C6 numeric-only array bounds tag ${tag} consumes its complete body`, async () => {
    const warnings: string[] = [];
    await readCodeViewC6Types(legacyReader(c6Type(142, tag === 2 ? [tag, 0, 10] : [tag, 0]), warnings));
    assert.deepEqual(warnings, []);
  });
}
