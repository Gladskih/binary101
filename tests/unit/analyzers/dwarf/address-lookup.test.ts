import assert from "node:assert/strict";
import { test } from "node:test";
import { readDwarfAddressLookup } from "../../../../analyzers/dwarf/address-lookup.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";
import { createListUnit } from "../../../fixtures/dwarf-lists-fixture.js";
import { concatenateBytes, encodeDwarf32Unit, encodeUint16, encodeUint32, encodeUint64 } from "../../../fixtures/dwarf-fixture-encoding.js";

const tableBytes = (tuples: number[]) => encodeDwarf32Unit(concatenateBytes(
  encodeUint16(2), encodeUint32(0), [8, 0], [0, 0, 0, 0], tuples
)); // The 12-byte header is padded to a 16-byte tuple boundary (DWARF 5 6.1.2).
const readTable = async (bytes: number[], issues: string[] = []) => readDwarfAddressLookup(
  dwarfMacroSources([{ name: ".debug_aranges", bytes }]).get(".debug_aranges")!,
  [createListUnit(4)], "little", issues
);

void test("address lookup tuples preserve their code coverage and CU linkage", async () => {
  const issues: string[] = [];

  const tables = await readTable(tableBytes(concatenateBytes(
    encodeUint64(0x1000), encodeUint64(7), encodeUint64(0), encodeUint64(0)
  )), issues);

  assert.deepEqual(tables[0]?.ranges, [{ start: 0x1000n, length: 7n, segment: null }]);
  assert.deepEqual(issues, []);
});

void test("address lookup reads segmented tuples using their actual encoded widths", async () => {
  const issues: string[] = [];
  const bytes = encodeDwarf32Unit(concatenateBytes(encodeUint16(2), encodeUint32(0),
    [2, 1], [0, 0, 0], [3], encodeUint16(10), encodeUint16(4), [0], encodeUint16(0), encodeUint16(0)));

  const tables = await readTable(bytes, issues);

  assert.deepEqual(tables[0]?.ranges, [{ segment: 3n, start: 10n, length: 4n }]);
  assert.match(issues.join(" "), /address-size mismatch/);
});

const malformed = [
  { name: "header", bytes: encodeDwarf32Unit([2]) },
  { name: "version", bytes: encodeDwarf32Unit(concatenateBytes(encodeUint16(9), encodeUint32(0), [8, 0])) },
  { name: "zero address size", bytes: encodeDwarf32Unit(concatenateBytes(encodeUint16(2), encodeUint32(0), [0, 0])) },
  { name: "tuple", bytes: tableBytes([1]) },
  { name: "overflow", bytes: tableBytes(concatenateBytes(encodeUint64(0xffffffffffffffffn), encodeUint64(2))) },
  { name: "missing terminator", bytes: tableBytes(concatenateBytes(encodeUint64(1), encodeUint64(1))) },
  { name: "trailing bytes", bytes: tableBytes(concatenateBytes(encodeUint64(0), encodeUint64(0), [1])) }
];
for (const example of malformed) {
  void test(`address lookup reports invalid ${example.name}`, async () => {
    const issues: string[] = [];

    await readTable(example.bytes, issues);

    assert.ok(issues.length > 0);
  });
}
