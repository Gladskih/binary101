import assert from "node:assert/strict";
import { test } from "node:test";
import { parseHll } from "../../../../../analyzers/pe/debug/hll.js";
import { createHll, hllModule, createHllSourceInspection } from "../../../../fixtures/pe-hll.js";
import { legacyU16, legacyU32, legacySymbol } from "../../../../fixtures/pe-legacy-codeview.js";
import { c6Symbol, c6Type, c6Index, c6Name } from "../../../../fixtures/pe-codeview-c6.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../../../../fixtures/pe-debug-extra-payloads.js";

const parse = async (bytes: Uint8Array) => {
  const source = createExtraDebugPayloadSubject(bytes);
  const warnings: string[] = [];
  const data = await parseHll(source.file, source.file.size, identityRvaToOff,
    0, source.offset, bytes.length, warning => warnings.push(warning));
  return { data, warnings };
};

void test("NB04 modules select their own HLL or CodeView stream dialect regardless of directory order", async () => {
  const hll = await parse(createHll());
  const cv = await parse(createHll([
    { type: 0x104, module: 1, data: Uint8Array.from([...legacyU32(1), ...legacySymbol()]) },
    { type: 0x101, module: 1, data: hllModule("CV", 0) }
  ]));
  assert.equal(hll.data?.signature, "NB04");
  assert.deepEqual(hll.data?.directories[0]!.subsections.map(section => section.data?.kind),
    ["module", "libraries", "symbols", "types"]);
  assert.deepEqual(hll.warnings, []);
  assert.deepEqual(cv.data?.directories[0]!.subsections[0]!.data,
    { kind: "symbols", records: [{ type: 0x203, name: "public_name" }] });
  assert.deepEqual(cv.warnings, []);
});

for (const version of [0x500, 0x600]) {
  void test(`NB04 module version ${version} retains compatible source names independently of type support`, async () => {
    const result = await parse(createHllSourceInspection(version));
    assert.deepEqual(result.data?.directories[0]?.subsections[1]?.data, {
      kind: "hllSource", files: [{ index: 1, name: "<source.c>" }],
      groups: [{ file: 1, segment: 1, category: "Source lines", values: [7] }]
    });
    assert.deepEqual(result.warnings, []);
  });
}

void test("NB04 directory header sizes and entry bounds are checked before decoding", async () => {
  const bytes = createHll([]);
  bytes.set(legacyU16(7), 8);
  const result = await parse(bytes);
  assert.equal(result.data, null);
  assert.match(result.warnings[0]!, /directory header/);
});

void test("NB04 malformed subsections preserve neighboring modules and unknown inventory", async () => {
  const { data, warnings } = await parse(createHll([
    { type: 0x101, module: 1, data: new Uint8Array(1) },
    { type: 0x999, module: 1, data: new Uint8Array(2) },
    { type: 0x101, module: 2, data: hllModule("HL", 0x400, "good.obj") }
  ]));
  assert.equal(data?.directories[0]!.subsections[0]!.data, undefined);
  assert.equal(data?.directories[0]!.subsections[1]!.data, undefined);
  assert.equal(data?.directories[0]!.subsections[2]!.data?.kind, "module");
  assert.equal(warnings.length, 1);
});

void test("NB04 retains C6 streams and refuses unknown module styles or missing descriptors", async () => {
  const result = await parse(createHll([
    { type: 0x101, module: 1, data: hllModule("CV", 0) },
    { type: 0x103, module: 1, data: Uint8Array.from(c6Type(93, [...c6Index(), ...c6Name("Alias")])) },
    { type: 0x104, module: 1, data: Uint8Array.from(c6Symbol(2)) },
    { type: 0x101, module: 2, data: hllModule("??", 0) },
    { type: 0x104, module: 2, data: Uint8Array.from(c6Symbol(2)) },
    { type: 0x104, module: 3, data: Uint8Array.from(c6Symbol(2)) }
  ]));
  const data = result.data!.directories[0]!.subsections;
  assert.deepEqual(data[1]!.data, { kind: "types", encoding: "c6", records: [{ type: 93, name: "Alias" }] });
  assert.deepEqual(data[2]!.data, { kind: "symbols", encoding: "c6", records: [{ type: 2 }] });
  assert.equal(data[4]!.data, undefined);
  assert.equal(result.warnings.length, 2);
  assert.match(result.warnings[0]!, /Unknown HLL module style/);
  assert.match(result.warnings[1]!, /no readable module descriptor/);
});

void test("NB04 short headers, unsupported signatures and out-of-bounds subsections are diagnosed", async () => {
  const bytes = createHll();
  const directory = new DataView(bytes.buffer).getUint32(4, true);
  bytes.set(legacyU32(0xffffffff), directory + 8 + 4);
  const result = await parse(bytes);
  assert.equal(result.data?.directories[0]!.subsections[0]!.data, undefined);
  assert.match(result.warnings[0]!, /outside payload bounds/);
  assert.equal((await parse(Uint8Array.from([78, 66, 48, 50, 0, 0, 0, 0]))).data, null);
  assert.equal((await parse(new Uint8Array(3))).data, null);
  assert.equal((await parse(new Uint8Array())).data, null);
});

void test("NB04 repeated subsection references share one decoded object", async () => {
  const bytes = createHll();
  const directory = new DataView(bytes.buffer).getUint32(4, true);
  // Reuse the first module's descriptor in a second directory entry.
  bytes.copyWithin(directory + 8 + 12, directory + 8, directory + 8 + 12);
  const { data } = await parse(bytes);
  const entries = data!.directories[0]!.subsections;
  assert.equal(entries[0]!.data, entries[1]!.data);
});

void test("NB04 recognizes C7 type streams even when the module style and version are unspecified", async () => {
  const result = await parse(createHll([
    { type: 0x101, module: 1, data: hllModule("\0\0", 0) },
    { type: 0x103, module: 1, data: Uint8Array.from([...legacyU32(1), 2, 0, 0x77, 0x77]) }
  ]));
  assert.deepEqual(result.data!.directories[0]!.subsections[1]!.data,
    { kind: "types", records: [{ type: 0x7777, index: 0x1000 }] });
  assert.deepEqual(result.warnings, []);
});

void test("NB04 source subsections use the module version and retain unsupported versions visibly", async () => {
  const result = await parse(createHll([
    { type: 0x101, module: 1, data: hllModule() },
    { type: 0x10b, module: 1, data: new Uint8Array() },
    { type: 0x10b, module: 2, data: new Uint8Array() }
  ]));
  assert.deepEqual(result.data!.directories[0]!.subsections[1]!.data, { kind: "hllSource", files: [], groups: [] });
  assert.match(result.warnings[0]!, /Unsupported HLL source format version 0/);
});

void test("NB04 zero-size subsections may end exactly at the payload boundary", async () => {
  const bytes = createHll([{ type: 0x999, module: 1, data: new Uint8Array() }]);
  const directory = new DataView(bytes.buffer).getUint32(4, true);
  bytes.set(legacyU32(bytes.length - 8), directory + 8 + 4);
  const result = await parse(bytes);
  assert.deepEqual(result.warnings, []);
  assert.equal(result.data!.directories[0]!.subsections[0]!.data, undefined);
});

void test("NB04 trailer is metadata and mismatched lengths remain visible", async () => {
  const bytes = createHll([]);
  bytes.set(legacyU32(16), bytes.length - 4);
  const result = await parse(bytes);
  assert.match(result.warnings[0]!, /trailer backward distance/);
  assert.equal(result.data?.signature, "NB04");
  const withoutFooter = await parse(createHll([]).slice(0, -8));
  assert.deepEqual(withoutFooter.warnings, []);
  assert.match((await parse(new Uint8Array(8))).warnings[0]!, /Unsupported HLL signature/);
});

void test("NB04 never interprets its terminal trailer as directory-entry bytes", async () => {
  const bytes = createHll([]);
  bytes.set(legacyU32(1), 12);
  const result = await parse(bytes);
  assert.equal(result.data?.signature, "NB04");
  assert.deepEqual(result.data?.directories[0]!.subsections, []);
  assert.match(result.warnings[0]!, /directory entries extend past payload bounds/);
  assert.match((await parse(new Uint8Array())).warnings[0]!, /^HLL debug entry/);
});

void test("NB04 C7 signature alone denotes an empty module stream", async () => {
  const result = await parse(createHll([
    { type: 0x101, module: 1, data: hllModule("CV", 0) },
    { type: 0x104, module: 1, data: Uint8Array.from(legacyU32(1)) }
  ]));
  assert.deepEqual(result.data?.directories[0]!.subsections[1]!.data, { kind: "symbols", records: [] });
  assert.deepEqual(result.warnings, []);
});

void test("NB04 unknown subsection inventory still validates ranges against header and payload", async () => {
  const bytes = createHll([{ type: 0x999, module: 1, data: new Uint8Array() }]);
  const directory = new DataView(bytes.buffer).getUint32(4, true);
  bytes.set(legacyU32(0), directory + 12);
  const header = await parse(bytes);
  assert.match(header.warnings[0]!, /outside payload bounds/);
  bytes.set(legacyU32(bytes.length), directory + 12);
  const outside = await parse(bytes);
  assert.match(outside.warnings[0]!, /outside payload bounds/);
});
