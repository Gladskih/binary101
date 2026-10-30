import assert from "node:assert/strict";
import { test } from "node:test";
import { parseTd32 } from "../../../../../analyzers/pe/debug/td32.js";
import { createTd32, td32Module, td32Names, td32Symbol } from "../../../../fixtures/pe-td32.js";
import { legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";
import { createPeWithDebugPayloads } from "../../../../fixtures/pe-debug-file.js";
import { parsePeHeaders } from "../../../../../analyzers/pe/core/index.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../../../../fixtures/pe-debug-extra-payloads.js";

const parse = async (bytes: Uint8Array, declaredSize = bytes.length) => {
  const subject = createExtraDebugPayloadSubject(bytes, declaredSize);
  const warnings: string[] = [];
  const parsed = await parseTd32(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, declaredSize, warning => warnings.push(warning));
  return { parsed, warnings };
};

void test("TD32 retains names and decodes modules, symbols and source lines", async () => {
  const { parsed, warnings } = await parse(createTd32());

  assert.equal(parsed?.signature, "FB09");
  assert.deepEqual(parsed?.directories[0]?.subsections.map(section => section.data?.kind),
    ["names", "module", "symbols", "source"]);
  assert.deepEqual(warnings, []);
});

void test("TD32 trailer locates FB0A data after a prefix without decoding unrelated bytes", async () => {
  const bytes = createTd32(undefined, "FB0A");

  const result = await parse(Uint8Array.from([...new Array<number>(12).fill(0), ...bytes]));

  assert.equal(result.parsed?.signature, "FB0A");
  assert.deepEqual(result.warnings, []);
  assert.equal((await parse(new Uint8Array(8))).parsed, null);
  assert.equal((await parse(new Uint8Array(7))).parsed, null);
  assert.deepEqual((await parse(new Uint8Array(7))).warnings, []);
  assert.equal((await parse(new Uint8Array())).parsed, null);
});

void test("TD32 accepts the minimum matching trailer and exact subsection end bounds", async () => {
  const minimal = Uint8Array.from([70, 66, 48, 57, ...legacyU32(0), 70, 66, 48, 57, ...legacyU32(16)]);
  const result = await parse(minimal);
  const bytes = createTd32([{ type: 0x999, module: 0, data: new Uint8Array() }]);
  bytes.set(legacyU32(bytes.length), 32);
  bytes.set(legacyU32(0), 28);
  const exact = await parse(bytes);

  assert.equal(result.parsed?.signature, "FB09");
  assert.deepEqual(result.warnings, ["TD32 directory offset is zero."]);
  assert.deepEqual(exact.warnings, ["TD32 subsection 2457 has no semantic decoder; its payload is retained in the inventory."]);
});

for (const section of [
  { type: 0x120, module: 1, data: td32Module(4) },
  { type: 0x125, module: 1, data: Uint8Array.from([...legacyU32(1), ...td32Symbol(0x205, 4)]) }
]) {
  void test(`TD32 diagnoses an isolated name reference in subsection ${section.type}`, async () => {
    const result = await parse(createTd32([
      { type: 0x130, module: 0, data: td32Names(["one"]) }, section
    ]));

    assert.deepEqual(result.warnings, ["TD32 name reference is outside the shared name table."]);
  });
}

void test("TD32 reports its own format name in ANSI and directory diagnostics", async () => {
  const result = await parse(createTd32([{ type: 0x125, module: 0,
    data: Uint8Array.from([...legacyU32(1), 8, 0, 1, 0, 3, 0, 0, 0, 1, 0x80]) }]));

  assert.deepEqual(result.warnings,
    ["TD32 ANSI code page is not recorded; non-ASCII text is shown as Windows-1252."]);
});

void test("TD32 does not accept a matching pair of unrecognized signatures", async () => {
  const bytes = Uint8Array.from([65, 66, 67, 68, ...legacyU32(0), 65, 66, 67, 68, ...legacyU32(16)]);

  const result = await parse(bytes);

  assert.equal(result.parsed, null);
  assert.deepEqual(result.warnings, []);
});

for (const size of [0, 8, 15]) {
  void test(`TD32 warns for undersized trailer displacement ${size} while retaining its header`, async () => {
    const bytes = createTd32();
    bytes.set(legacyU32(size), bytes.length - 4);
    const result = await parse(bytes);

    assert.equal(result.parsed?.signature, "FB09");
    assert.deepEqual(result.warnings, ["TD32 trailer is missing, inconsistent or out of bounds."]);
  });
}

void test("TD32 validates bounds even for unknown subsection kinds", async () => {
  const bytes = createTd32([{ type: 0x999, module: 0, data: new Uint8Array() }]);
  bytes.set(legacyU32(bytes.length - 1), 28);
  bytes.set(legacyU32(2), 32);
  const result = await parse(bytes);

  assert.deepEqual(result.warnings, ["TD32 subsection 2457: Error: TD32 subsection exceeds payload bounds."]);
});

void test("TD32 reports missing names rather than resolving an invented fallback table", async () => {
  const result = await parse(createTd32([{ type: 0x120, module: 1, data: td32Module(1) }]));

  assert.deepEqual(result.warnings, ["TD32 name reference is outside the shared name table."]);
});

void test("TD32 validates isolated source-file name references", async () => {
  const bytes = Uint8Array.from([1, 0, 0, 0, ...legacyU32(8), 0, 0, ...legacyU32(1)]);
  const result = await parse(createTd32([{ type: 0x127, module: 1, data: bytes }]));

  assert.deepEqual(result.warnings, ["TD32 name reference is outside the shared name table."]);
});

void test("TD32 type tables integrate with the directory and validate their name references", async () => {
  const type = td32Symbol(4, 2, 24);
  type.push(12, 0); // Immediate numeric size after the shared name index.
  type.splice(0, 2, type.length - 2, 0);
  const result = await parse(createTd32([
    { type: 0x130, module: 0, data: td32Names(["one"]) },
    { type: 0x12b, module: 0, data: Uint8Array.from([
      ...legacyU32(1), ...legacyU32(1), ...legacyU32(12), ...type]) }
  ]));

  assert.deepEqual(result.parsed?.directories[0]?.subsections[1]?.data,
    { kind: "types", version: 1, records: [{ index: 0, type: 4, nameIndex: 2, body: {
      count: 0, fieldList: 0, attributes: 0, relation12: 0, relation16: 0, relation20: 0, byteSize: { value: "12" }
    } }] });
  assert.deepEqual(result.warnings, ["TD32 name reference is outside the shared name table."]);
});

void test("TD32 invalid trailers preserve recognized headers with an explicit warning", async () => {
  const bytes = createTd32();
  bytes.set(legacyU32(0xffffffff), bytes.length - 4);
  const result = await parse(bytes);
  const short = await parse(createTd32().subarray(0, 8));

  assert.equal(result.parsed?.signature, "FB09");
  assert.match(result.warnings.join(" | "), /trailer/);
  assert.equal(short.parsed?.directories.length, 0);
  assert.match(short.warnings.join(" | "), /bounds/);
});

void test("TD32 caches both successful and failed subsection decodes", async () => {
  const bytes = createTd32([{ type: 0x120, module: 1, data: td32Module(0) },
    { type: 0x120, module: 2, data: td32Module(0) },
    { type: 0x120, module: 3, data: new Uint8Array(1) },
    { type: 0x120, module: 4, data: new Uint8Array(1) }]);
  bytes.set(bytes.subarray(28, 36), 40);
  bytes.set(bytes.subarray(52, 60), 64);
  const { parsed, warnings } = await parse(bytes);
  const sections = parsed!.directories[0]!.subsections;

  assert.ok(sections[0]!.data);
  assert.equal(sections[0]!.data, sections[1]!.data);
  assert.equal(sections[2]!.data, undefined);
  assert.equal(sections[3]!.data, undefined);
  assert.equal(warnings.length, 1);
});

void test("TD32 bounds-checks directory entries and retains opaque type inventory", async () => {
  const bytes = createTd32([{ type: 0x999, module: 0xffff, data: new Uint8Array() },
    { type: 0x120, module: 1, data: td32Module() }]);
  bytes.set(legacyU32(0xffffffff), 40);
  const result = await parse(bytes);

  assert.equal(result.parsed?.directories[0]?.subsections.length, 2);
  assert.match(result.warnings.join(" | "), /no semantic decoder/);
  assert.match(result.warnings.join(" | "), /bounds/);
});

void test("TD32 invalid name references and ambiguous name tables stay visible", async () => {
  const { warnings } = await parse(createTd32([
    { type: 0x130, module: 0xffff, data: td32Names(["one"]) },
    { type: 0x130, module: 0xffff, data: td32Names(["two"]) },
    { type: 0x120, module: 1, data: td32Module(4) },
    { type: 0x125, module: 1, data: Uint8Array.from([...legacyU32(1), 2, 0, 6, 0, ...td32Symbol()]) }
  ]));

  assert.match(warnings.join(" | "), /multiple name tables/);
  assert.match(warnings.join(" | "), /outside the shared name table/);
});

void test("TD32 declared size truncation is diagnosed without reading outside actual data", async () => {
  const { parsed, warnings } = await parse(createTd32(), 100000);

  assert.equal(parsed?.signature, "FB09");
  assert.match(warnings.join(" | "), /shorter than.*SizeOfData/);
});

void test("TD32 rejects oversized subsection ranges and inconsistent trailer signatures", async () => {
  const bytes = createTd32();
  bytes.set(legacyU32(0xffffffff), 32);
  bytes[bytes.length - 5] = 65; // Footer FB0A does not match the FB09 header.
  const result = await parse(bytes);

  assert.match(result.warnings.join(" | "), /trailer/);
  assert.match(result.warnings.join(" | "), /subsection exceeds payload bounds/);
  assert.equal(result.parsed?.directories[0]?.subsections[0]?.data, undefined);
});

void test("TD32 read failures become warnings rather than escaping the parser", async context => {
  const subject = createExtraDebugPayloadSubject(createTd32());
  context.mock.method(subject.file, "read", async () => { throw new Error("read failed"); });
  const warnings: string[] = [];

  const result = await parseTd32(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, subject.declaredSize, warning => warnings.push(warning));

  assert.equal(result, null);
  assert.match(warnings.join(" | "), /read failed/);
});

for (const type of [0, 9]) {
  void test(`TD32 integrates with debug type ${type} only for recognized signatures`, async () => {
    const file = createPeWithDebugPayloads([{ type, data: createTd32() }]);
    const pe = await parsePeHeaders(file);
    assert.ok(pe);
    const result = await parseDebugDirectory(file, pe.dataDirs, pe.rvaToOff, pe.coff.Machine);

    assert.equal(result.entries[0]?.td32?.signature, "FB09");
    assert.equal(result.entries[0]?.rawPayload, undefined);
    assert.equal(result.warning, null);
  });
}

void test("TD32 field member names participate in shared-name bounds checks", async () => {
  const field = [...legacyU16(0x406), ...legacyU32(0x74), ...legacyU16(3),
    ...legacyU32(2), ...legacyU32(0), ...legacyU16(0)];
  const record = [...legacyU16(field.length + 2), ...legacyU16(0x204), ...field];
  const result = await parse(createTd32([
    { type: 0x130, module: 0, data: td32Names(["one"]) },
    { type: 0x12b, module: 0, data: Uint8Array.from([
      ...legacyU32(1), ...legacyU32(1), ...legacyU32(12), ...record]) }
  ]));
  assert.deepEqual(result.warnings, ["TD32 name reference is outside the shared name table."]);
});
