import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createTypeLibraryDecoder, readGuid, readMsftTables, TypeLibraryReader
} from "../../../../../analyzers/pe/type-library/reader.js";
import { createLibraryReader } from "../../../../fixtures/type-library.js";

void test("reader bounds-checks segments and signed offsets", () => {
  const reader = createLibraryReader("NameTab");
  assert.equal(reader.at("NameTab", 0, 128), 0);
  assert.equal(reader.at("NameTab", 128, 0), 128);
  assert.equal(reader.at("NameTab", -1, 1), null);
  assert.equal(reader.at("NameTab", 128, 1), null);
  assert.equal(reader.at("missing", 0, 0), null);
  assert.equal(reader.range(0, -1), false);
  assert.equal(reader.range(0.5, 1), false);
  assert.equal(reader.range(0, Infinity), false);
  assert.equal(reader.range(0, 1, 129), false);
});

void test("GUID formatting rejects invalid and truncated byte ranges", () => {
  const view = new DataView(new ArrayBuffer(16));
  assert.equal(readGuid(view, -1), null);
  assert.equal(readGuid(view, 1), null);
  assert.equal(readGuid(view, NaN), null);
});

void test("text reads cannot silently clamp invalid offsets", () => {
  const reader = createLibraryReader("NameTab", 1);
  assert.equal(reader.text(-1, 1), "");
  assert.equal(reader.text(0, 2), "");
  assert.deepEqual(reader.issues, ["TYPELIB text range is outside the resource."]);
});

for (const [lcid, encoding] of [[0x404, "big5"], [0x804, "gbk"], [0xc04, "big5"],
  [0x10411, "shift_jis"], [0x409, "windows-1252"], [0x41a, "windows-1250"],
  [0xc1a, "windows-1251"], [0x1c1a, "windows-1251"], [0x201a, "windows-1251"],
  [0x281a, "windows-1251"], [0x301a, "windows-1251"], [0x641a, "windows-1251"],
  [0x6c1a, "windows-1251"], [0x1041a, "windows-1250"]] as const) {
  void test(`locale ${lcid} selects its expected ANSI encoding`, () => {
    assert.equal(createTypeLibraryDecoder(lcid).encoding, encoding);
  });
}

void test("GUID table offsets are relative to the segment and support multiple records", () => {
  const reader = createLibraryReader("GuidTab", 72);
  reader.segments[0]!.offset = 24;
  reader.segments[0]!.length = 48;
  reader.view.setUint32(24, 1, true);
  reader.view.setUint32(48, 2, true);
  readMsftTables(reader);
  assert.equal(reader.guids.get(0), "00000001-0000-0000-0000-000000000000");
  assert.equal(reader.guids.get(24), "00000002-0000-0000-0000-000000000000");
});

void test("empty strings still occupy padded MSFT string records", () => {
  const reader = createLibraryReader("StringTab", 16);
  readMsftTables(reader);
  assert.deepEqual([...reader.strings], [[0, ""], [8, ""]]);
  assert.deepEqual(reader.issues, []);
});

void test("reader resolves present strings, absent sentinels and invalid references", () => {
  const reader = createLibraryReader("NameTab");
  reader.names.set(0, "");
  assert.equal(reader.lookup(reader.names, 0, "name"), "");
  assert.equal(reader.lookup(reader.names, -1, "name"), null);
  assert.equal(reader.lookup(reader.names, 1, "name"), null);
  assert.equal(reader.lookup(reader.names, 1, "name"), null);
  assert.equal(reader.issues.length, 1);
});

void test("reader merges new diagnostics and deduplicates existing messages", () => {
  const reader = new TypeLibraryReader(new Uint8Array(), [], ["Existing warning"]);
  reader.warn("Existing warning");
  reader.warn("New warning");
  reader.warn("New warning");
  assert.deepEqual(reader.issues, ["Existing warning", "New warning"]);
});

void test("GUID byte order respects little-endian integers and ordered Data4", () => {
  const data = Uint8Array.from([0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
  assert.equal(readGuid(new DataView(data.buffer), 0), "12345678-9abc-def0-1234-56789abcdef0");
});

void test("names and strings honor record padding and do not scan past segment ends", () => {
  const reader = createLibraryReader("NameTab", 16);
  reader.view.setUint8(8, 3);
  reader.data.set(new TextEncoder().encode("Lib"), 12);
  readMsftTables(reader);
  assert.equal(reader.names.get(0), "Lib");
  assert.deepEqual(reader.issues, []);
});

for (const [name, size] of [["NameTab", 11], ["StringTab", 1], ["GuidTab", 23]] as const) {
  void test(`${name} rejects a truncated record`, () => {
    const reader = createLibraryReader(name, size);
    readMsftTables(reader);
    assert.match(reader.issues.join(), /truncated/);
  });
}

for (const name of ["NameTab", "StringTab"] as const) {
  void test(`${name} rejects a text length beyond the segment`, () => {
    const reader = createLibraryReader(name, 16);
    reader.view.setUint16(name === "NameTab" ? 8 : 0, 255, true);
    readMsftTables(reader);
    assert.match(reader.issues.join(), /text is truncated/);
  });
}

void test("text encoding uses LCID evidence and preserves non-ASCII ANSI bytes", () => {
  const data = new Uint8Array(16);
  new DataView(data.buffer).setUint32(12, 0x419, true);
  data[0] = 0xc0;
  assert.equal(new TypeLibraryReader(data, [], []).text(0, 1), "А");
  assert.equal(new TypeLibraryReader(data.subarray(0, 1), [], []).text(0, 1), "À");
});
