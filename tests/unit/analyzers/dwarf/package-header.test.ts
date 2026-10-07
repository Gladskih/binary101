import assert from "node:assert/strict";
import { test } from "node:test";
import { readDwarfPackageHeader } from "../../../../analyzers/dwarf/package-header.js";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";
import { encodeDwarfPackageIndex } from "../../../fixtures/dwarf-package-fixture.js";
import { encodeUint32 } from "../../../fixtures/dwarf-fixture-encoding.js";

const readHeader = async (bytes: number[], byteOrder: "little" | "big" = "little") => {
  const source = dwarfMacroSources([{ name: ".debug_cu_index", bytes }]).get(".debug_cu_index")!;
  const issues: string[] = [];
  const cursor = new DwarfCursor(source.reader, source.section, 0, source.section.size,
    byteOrder === "little", issues);
  return { header: await readDwarfPackageHeader(cursor, byteOrder), position: cursor.position, issues };
};

void test("package headers validate GNU2 and standard5 layouts before reading their arrays", async () => {
  const standard = await readHeader(encodeDwarfPackageIndex());
  const gnu = await readHeader(encodeDwarfPackageIndex(0n, 2));
  assert.deepEqual(standard.header, { version: 5, sectionCount: 2, unitCount: 1, slotCount: 2 });
  assert.deepEqual(gnu.header, { version: 2, sectionCount: 2, unitCount: 1, slotCount: 2 });
  assert.equal(standard.position, 16);
  assert.deepEqual(standard.issues, []);
});

void test("big endian package headers distinguish the v5 uhalf version from the GNU2 uword", async () => {
  const standard = await readHeader([0, 5, 0, 0, ...new Array<number>(12).fill(0)], "big");
  const gnu = await readHeader([0, 0, 0, 2, ...new Array<number>(12).fill(0)], "big");
  assert.equal(standard.header?.version, 5);
  assert.equal(gnu.header?.version, 2);
  assert.deepEqual(standard.issues, []);
  assert.deepEqual(gnu.issues, []);
});

void test("package headers reject invalid versions, padding, and every truncated header field", async () => {
  const results = await Promise.all([[3, 0, 0, 0], [5, 0, 1, 0], [], [5, 0, 0, 0],
    [5, 0, 0, 0, 0, 0, 0, 0], new Array<number>(12).fill(0).map((value, index) => index ? value : 5)]
    .map(bytes => readHeader(bytes)));
  assert.ok(results.every(result => result.header === null));
  assert.ok(results.every(result => result.issues.length > 0));
});

void test("nonempty package headers require both section columns and signature slots", async () => {
  const columns = await readHeader([5, 0, 0, 0, ...[0, 1, 2].flatMap(encodeUint32)]);
  const slots = await readHeader([5, 0, 0, 0, ...[1, 1, 0].flatMap(encodeUint32)]);
  assert.equal(columns.header, null);
  assert.equal(slots.header, null);
  assert.match(columns.issues.join(" "), /no section columns or signature slots/);
  assert.match(slots.issues.join(" "), /no section columns or signature slots/);
});

void test("package preflight includes signature slots, column ids and both matrices", async () => {
  const bytes = encodeDwarfPackageIndex();
  const exact = await readHeader(bytes);
  const short = await readHeader(bytes.slice(0, -1));
  const huge = await readHeader([5, 0, 0, 0, ...new Array<number>(12).fill(255)]);
  assert.ok(exact.header);
  assert.equal(short.header, null);
  assert.equal(huge.header, null);
  assert.match(short.issues.join(" "), /arrays exceed/);
});

void test("invalid versions and padding cannot be hidden by a later truncated count field", async () => {
  const version = await readHeader([3, 0, 0, 0, ...new Array<number>(12).fill(0)]);
  const padding = await readHeader([5, 0, 1, 0, ...new Array<number>(12).fill(0)]);
  assert.equal(version.header, null);
  assert.equal(padding.header, null);
  assert.match(version.issues.join(" "), /version or padding/);
  assert.match(padding.issues.join(" "), /version or padding/);
});
