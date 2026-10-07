import assert from "node:assert/strict";
import { test } from "node:test";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";
import { readDwarfNameIndexHeader } from "../../../../analyzers/dwarf/name-index-header.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";
import { concatenateBytes, encodeUint16, encodeUint32 } from "../../../fixtures/dwarf-fixture-encoding.js";

const header = (fields: number[], version = 5, padding = 0): number[] =>
  concatenateBytes(encodeUint16(version), encodeUint16(padding), fields.flatMap(encodeUint32));
const readHeader = async (bytes: number[], format: 32 | 64 = 32) => {
  const issues: string[] = [];
  const source = dwarfMacroSources([{ name: ".debug_names", bytes }]).get(".debug_names")!;
  const cursor = new DwarfCursor(source.reader, source.section, 0, bytes.length, true, issues);
  return { value: await readDwarfNameIndexHeader(cursor, format), issues, position: cursor.position };
};

void test("name index headers retain all counts and aligned augmentation text", async () => {
  const result = await readHeader(concatenateBytes(header([1, 2, 3, 2, 4, 6, 4]),
    [76, 76, 86, 0], new Array<number>(130).fill(0)));

  assert.deepEqual(result.value, { compileUnitCount: 1, localTypeUnitCount: 2,
    foreignTypeUnitCount: 3, bucketCount: 2, nameCount: 4, abbreviationSize: 6, augmentation: "LLV" });
  assert.equal(result.position, 36);
  assert.deepEqual(result.issues, []);
});

void test("empty DWARF64 index headers allow omitted hashing arrays", async () => {
  const result = await readHeader(header([0, 0, 0, 0, 0, 0, 0]), 64);

  assert.deepEqual(result.value, { compileUnitCount: 0, localTypeUnitCount: 0,
    foreignTypeUnitCount: 0, bucketCount: 0, nameCount: 0, abbreviationSize: 0, augmentation: "" });
  assert.deepEqual(result.issues, []);
});

const invalid = [
  { name: "truncated version", bytes: [5] },
  { name: "wrong version", bytes: header([], 4) },
  { name: "nonzero padding", bytes: header([], 5, 1) },
  { name: "truncated counts", bytes: header([0, 0]) },
  { name: "missing CU array", bytes: header([1, 0, 0, 0, 0, 0, 0]) },
  { name: "missing local TU array", bytes: header([0, 1, 0, 0, 0, 0, 0]) },
  { name: "missing foreign TU array", bytes: header([0, 0, 1, 0, 0, 0, 0]) },
  { name: "missing bucket array", bytes: header([0, 0, 0, 1, 0, 0, 0]) },
  { name: "missing name arrays", bytes: header([0, 0, 0, 0, 1, 0, 0]) },
  { name: "missing abbreviations", bytes: header([0, 0, 0, 0, 0, 1, 0]) },
  { name: "missing augmentation", bytes: header([0, 0, 0, 0, 0, 0, 4]) },
  { name: "misaligned augmentation", bytes: concatenateBytes(header([0, 0, 0, 0, 0, 0, 1]), [0]) }
];
for (const example of invalid) {
  void test(`name index headers reject ${example.name}`, async () => {
    const result = await readHeader(example.bytes);

    assert.equal(result.value, null);
    assert.equal(result.issues.length, 1);
  });
}
