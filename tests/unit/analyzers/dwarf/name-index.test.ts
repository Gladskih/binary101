import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { readDwarfNameIndex } from "../../../../analyzers/dwarf/name-index.js";
import { DwarfStringReader } from "../../../../analyzers/dwarf/strings.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";
import { createListUnit } from "../../../fixtures/dwarf-lists-fixture.js";
import { createDwarfNameIndexFixture, encodeDwarfNameIndex } from "../../../fixtures/dwarf-name-index-fixture.js";
import { concatenateBytes, encodeCString, encodeDwarf32Unit, encodeUint32 } from "../../../fixtures/dwarf-fixture-encoding.js";

const readIndex = async (bytes: number[], issues: string[] = []) => {
  const sections = dwarfMacroSources([{ name: ".debug_names", bytes },
    { name: ".debug_str", bytes: encodeCString("main.c") }]);
  return readDwarfNameIndex(sections.get(".debug_names")!, [createListUnit(5)], "little",
    new DwarfStringReader(sections, "little", issues), issues);
};
const abbreviations = [1, 0x11, 3, 0x13, 0, 0, 0];

void test("name indexes retain identifiers and CU/DIE references without hashes", async () => {
  const fixture = createDwarfNameIndexFixture();

  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);

  assert.equal(dwarf.nameIndexes?.length, 1);
  assert.deepEqual(dwarf.nameIndexes?.[0]?.compileUnits, [0n]);
  assert.deepEqual(dwarf.nameIndexes?.[0]?.names[0]?.name, { kind: "string", value: "calculate" });
  assert.equal(dwarf.nameIndexes?.[0]?.names[0]?.entries[0]?.tag, 0x2e);
  assert.deepEqual(dwarf.issues, []);
});

void test("name indexes read hash buckets and reuse identical entry lists", async () => {
  const issues: string[] = [];
  const indexes = await readIndex(encodeDwarfNameIndex(abbreviations,
    concatenateBytes([1], encodeUint32(12), [0]), [0, 0], [1], [1, 2]), issues);

  assert.deepEqual(indexes[0]?.buckets, [1]);
  assert.deepEqual(indexes[0]?.names.map(name => name.hash), [1, 2]);
  assert.equal(indexes[0]?.names[0]?.entries, indexes[0]?.names[1]?.entries);
  assert.deepEqual(issues, []);
});

const malformed = [
  { name: "header", bytes: encodeDwarf32Unit([5, 0, 0]) },
  { name: "version", bytes: encodeDwarf32Unit([6, 0, 0, 0]) },
  { name: "counts", bytes: encodeDwarf32Unit(concatenateBytes([5, 0, 0, 0], encodeUint32(0xffffffff))) },
  { name: "unknown entry", bytes: encodeDwarfNameIndex(abbreviations, [9, 0]) },
  { name: "entry terminator", bytes: encodeDwarfNameIndex(abbreviations, concatenateBytes([1], encodeUint32(12))) },
  { name: "entry pool offset", bytes: encodeDwarfNameIndex(abbreviations, [0], [99]) },
  { name: "abbreviation tag", bytes: encodeDwarfNameIndex([1, 0, 0], [0]) },
  { name: "abbreviation attr pair", bytes: encodeDwarfNameIndex([1, 0x11, 0, 0x13], [0]) },
  { name: "abbreviation attr terminator", bytes: encodeDwarfNameIndex([1, 0x11, 3, 0x13], [0]) },
  { name: "missing abbreviation terminator", bytes: encodeDwarfNameIndex([1, 0x11, 0, 0], [0]) },
  { name: "missing DIE", bytes: encodeDwarfNameIndex(abbreviations, concatenateBytes([1], encodeUint32(99), [0])) },
  { name: "bucket entry", bytes: encodeDwarfNameIndex(abbreviations, [0], [0], [99], [1]) }
];
for (const example of malformed) {
  void test(`name indexes report invalid ${example.name}`, async () => {
    const issues: string[] = [];

    await readIndex(example.bytes, issues);

    assert.ok(issues.length > 0);
  });
}
