import assert from "node:assert/strict";
import { test } from "node:test";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";
import { readDwarfLineTables } from "../../../../analyzers/dwarf/line-tables.js";
import { createDwarfSectionFile } from "../../../fixtures/dwarf-semantic-fixture.js";
import { concatenateBytes, encodeCString, encodeUint32, encodeUleb } from "../../../fixtures/dwarf-fixture-encoding.js";

const readTables = async (bytes: number[], version = 5, issues: string[] = []) => {
  const fixture = createDwarfSectionFile([
    { name: ".debug_line", bytes }, { name: ".debug_str", bytes: encodeCString("shared.c") },
    { name: ".debug_line_str", bytes: encodeCString("src") }
  ]);
  const section = fixture.sections[0]!;
  return readDwarfLineTables(new DwarfCursor(fixture.file, section, 0, bytes.length, true, issues),
    version, { sections: new Map(fixture.sections.map(section => [section.name, {
      section, summary: section, reader: fixture.file, decoded: true
    }])), littleEndian: true, issues, dwarfFormat: 32 });
};

void test("line tables preserve paths, directory indices, time, size, and source checksums", async () => {
  // DWARF 5 Table 6.6 / 7.5: path(strp), directory(udata), timestamp(data4), size(data1), MD5(data16).
  const bytes = concatenateBytes([1, 1, 0x1f, 1], encodeUint32(0),
    [5, 1, 0x0e, 2, 0x0f, 3, 0x06, 4, 0x0b, 5, 0x1e, 1],
    encodeUint32(0), [0], encodeUint32(123), [42], new Array<number>(16).fill(7));

  assert.deepEqual(await readTables(bytes), { directories: ["src"], files: [{
    path: "shared.c", directoryIndex: 0n, timestamp: 123n, size: 42n,
    md5: new Uint8Array(16).fill(7)
  }] });
  assert.deepEqual(await readTables(concatenateBytes(encodeCString("src"), [0],
    encodeCString("main.c"), [1, 2, 3, 0]), 4), {
    directories: ["src"], files: [{ path: "main.c", directoryIndex: 1n, timestamp: 2n, size: 3n }]
  });
  assert.deepEqual(await readTables([0, 0, 0, 0]), { directories: [], files: [] });
});

const badTables = [
  { name: "format count", bytes: [] },
  { name: "format content", bytes: [1, 0x80] },
  { name: "format form", bytes: [1, 1] },
  { name: "entry count", bytes: [0] },
  { name: "count without formats", bytes: [0, 1, 0] },
  { name: "extreme count", bytes: concatenateBytes([0], encodeUleb(1n << 60n)) },
  { name: "unknown form", bytes: [1, 1, 0x7f, 1, 0] },
  { name: "inline path", bytes: [1, 1, 0x08, 1, 65] },
  { name: "variable index", bytes: [1, 2, 0x0f, 1, 0x80] },
  { name: "fixed value", bytes: [1, 3, 0x06, 1, 0] },
  { name: "checksum", bytes: [1, 5, 0x1e, 1, 0] },
  { name: "string pointer", bytes: [1, 1, 0x0e, 1, 0] },
  { name: "file format", bytes: [0, 0, 1] },
  { name: "file count", bytes: [0, 0, 0] }
];
for (const example of badTables) {
  void test(`line tables reject truncated or invalid ${example.name}`, async () => {
    const issues: string[] = [];

    assert.equal(await readTables(example.bytes, 5, issues), null);
    assert.ok(issues.length > 0);
  });
}

void test("line tables accept unresolved paths while recording the offending string offset", async () => {
  const issues: string[] = [];

  assert.deepEqual(await readTables(concatenateBytes([1, 1, 0x1f, 1], encodeUint32(99), [0, 0]),
    5, issues), { directories: [""], files: [] });
  assert.match(issues.join(" "), /string offset 99.*outside/);
  assert.equal(await readTables([0, 65], 4, issues), null);
  assert.equal(await readTables([65], 4, issues), null);
  assert.equal(await readTables([0, 65, 0, 0], 4, issues), null);
});
