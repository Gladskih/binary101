import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { createDwarfSemanticFixture, createDwarfSectionFile } from "../../../fixtures/dwarf-semantic-fixture.js";
import {
  encodeAbbreviationTable, encodeDwarf32Unit, concatenateBytes,
  encodeUint16, encodeUint32, encodeUint8, encodeUleb
} from "../../../fixtures/dwarf-fixture-encoding.js";

void test("DWARF preserves all child attributes and the actual DIE hierarchy", async () => {
  const fixture = createDwarfSemanticFixture();

  const result = await analyzeDwarf(fixture.file, fixture.sections, true);

  assert.equal(result.units[0]?.dies.length, 4);
  assert.equal(result.units[0]?.dies[3]?.parentOffset, fixture.functionOffset);
  assert.deepEqual(result.units[0]?.dies[2]?.attributes[1], {
    name: 0x49, form: 0x13, value: { kind: "unsigned", value: BigInt(fixture.typeOffset) }
  }); // DW_AT_type / DW_FORM_ref4 (DWARF 5 Tables 7.5 and 7.17).
  assert.deepEqual(result.units[0]?.dies[3]?.attributes[2]?.value, {
    kind: "expression", operations: [{ offset: 0, opcode: 0x91, operands: [-8n] }]
  }); // DW_OP_fbreg -8 (7.7.1).
  assert.deepEqual(result.issues, []);
});

const createHierarchyFixture = (codes: number[]) => createDwarfSectionFile([
  { name: ".debug_info", bytes: encodeDwarf32Unit(concatenateBytes(
    encodeUint16(4), encodeUint32(0), encodeUint8(8), codes.flatMap(encodeUleb)
  )) },
  { name: ".debug_abbrev", bytes: encodeAbbreviationTable([
    { code: 1, tag: 0x11, children: 1, attributes: [] },
    { code: 2, tag: 0x2e, children: 0, attributes: [] }
  ]) }
]);

void test("DWARF reports an unterminated child list while retaining complete DIEs", async () => {
  const fixture = createHierarchyFixture([1, 2]);

  const result = await analyzeDwarf(fixture.file, fixture.sections, true);

  assert.equal(result.units[0]?.dies.length, 2);
  assert.match(result.issues.join(" "), /Unterminated DIE child list/);
});

void test("DWARF reports unexpected nulls and multiple roots", async () => {
  const nullFixture = createHierarchyFixture([0]);
  const rootsFixture = createHierarchyFixture([2, 2]);

  const unexpected = await analyzeDwarf(nullFixture.file, nullFixture.sections, true);
  const multiple = await analyzeDwarf(rootsFixture.file, rootsFixture.sections, true);

  assert.match(unexpected.issues.join(" "), /Unexpected null DIE/);
  assert.match(multiple.issues.join(" "), /Multiple root DIEs/);
});
