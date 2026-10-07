import assert from "node:assert/strict";
import { test } from "node:test";
import { readDwarfPublicNames } from "../../../../analyzers/dwarf/public-names.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";
import { createListUnit } from "../../../fixtures/dwarf-lists-fixture.js";
import {
  concatenateBytes, encodeCString, encodeDwarf32Unit, encodeDwarf64Unit,
  encodeUint16, encodeUint32, encodeUint64
} from "../../../fixtures/dwarf-fixture-encoding.js";

const readTable = async (bytes: number[], issues: string[] = [], name = ".debug_pubnames") =>
  readDwarfPublicNames(dwarfMacroSources([{ name, bytes }]).get(name)!, [createListUnit(4)], "little", issues);
const publicTable = (entry: number[]) => encodeDwarf32Unit(concatenateBytes(
  encodeUint16(2), encodeUint32(0), encodeUint32(4), entry
));

void test("public names preserve source identifiers and validate CU-relative DIE references", async () => {
  const issues: string[] = [];

  const tables = await readTable(publicTable(concatenateBytes(
    encodeUint32(12), encodeCString("compute"), encodeUint32(0)
  )), issues);

  assert.deepEqual(tables[0]?.entries, [{ dieOffset: 12n, name: "compute", descriptor: null }]);
  assert.deepEqual(issues, []);
  assert.deepEqual((await readTable(encodeDwarf64Unit(concatenateBytes(encodeUint16(2),
    encodeUint64(0), encodeUint64(4), encodeUint64(12), [0x91], encodeCString("int"),
    encodeUint64(0))), issues, ".debug_gnu_pubtypes"))[0]?.entries,
  [{ dieOffset: 12n, name: "int", descriptor: 0x91 }]);
});

const malformed = [
  { name: "length", bytes: [1] },
  { name: "version", bytes: encodeDwarf32Unit(encodeUint16(9)) },
  { name: "header", bytes: encodeDwarf32Unit(encodeUint16(2)) },
  { name: "name", bytes: publicTable(concatenateBytes(encodeUint32(12), [65])) },
  { name: "missing terminator", bytes: publicTable(concatenateBytes(encodeUint32(12), encodeCString("a"))) },
  { name: "unresolved DIE", bytes: publicTable(concatenateBytes(encodeUint32(99), encodeCString("a"), encodeUint32(0))) },
  { name: "trailing bytes", bytes: publicTable(concatenateBytes(encodeUint32(0), [1])) }
];
for (const example of malformed) {
  void test(`public names report malformed ${example.name}`, async () => {
    const issues: string[] = [];

    await readTable(example.bytes, issues);

    assert.ok(issues.length > 0);
  });
}

void test("public names warn for missing CU, mismatched CU lengths, and missing GNU descriptors", async () => {
  const issues: string[] = [];
  const source = dwarfMacroSources([{ name: ".debug_pubnames", bytes: encodeDwarf32Unit(
    concatenateBytes(encodeUint16(2), encodeUint32(0), encodeUint32(99), encodeUint32(0))
  ) }]).get(".debug_pubnames")!;

  await readDwarfPublicNames(source, [], "little", issues);
  await readDwarfPublicNames(source, [createListUnit(4)], "little", issues);
  await readTable(publicTable(encodeUint32(12)), issues, ".debug_gnu_pubnames");
  assert.match(issues.join(" "), /missing compilation unit/);
  assert.match(issues.join(" "), /length mismatch/);
  assert.match(issues.join(" "), /Truncated/);
});

void test("skeleton public names require their split unit instead of reporting every external DIE as malformed", async () => {
  const source = dwarfMacroSources([{ name: ".debug_pubnames", bytes: publicTable(concatenateBytes(
    encodeUint32(12), encodeCString("compute"), encodeUint32(0)
  )) }]).get(".debug_pubnames")!;
  const skeleton = { ...createListUnit(5), unitType: 4, dwoId: 2n };
  const missing: string[] = [];
  const available: string[] = [];
  const noId: string[] = [];
  await readDwarfPublicNames(source, [skeleton], "little", missing);
  await readDwarfPublicNames(source, [skeleton,
    { ...createListUnit(5), sectionName: ".debug_info.dwo", dwoId: 2n }], "little", available);
  await readDwarfPublicNames(source, [{ ...createListUnit(5), unitType: 4 }], "little", noId);
  assert.equal(missing.length, 1);
  assert.match(missing[0]!, /external split compilation unit/);
  assert.deepEqual(available, []);
  assert.match(noId.join(" "), /external split/);
});
