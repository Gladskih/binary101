import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import {
  createDwarfDieIndex, inheritedDwarfAttribute, resolveDwarfReference, validateDwarfReferences
} from "../../../../analyzers/dwarf/references.js";
import { createDwarfSemanticFixture } from "../../../fixtures/dwarf-semantic-fixture.js";
import type { DwarfAttribute, DwarfDie, DwarfUnit } from "../../../../analyzers/dwarf/types.js";

// Reference forms/attributes are independent DWARF 5 Table 7.5/7.17 oracles.
const reference = (form: number, value: bigint): DwarfAttribute => ({
  name: 0x49, form, value: { kind: "unsigned", value }
});
const unit = (offset: number, dies: DwarfDie[]): DwarfUnit => ({
  offset, dies, sectionName: ".debug_info", length: 100n, format: 32,
  version: 4, unitType: null, addressSize: 8, abbreviationOffset: 0n
});
const die = (offset: number, attributes: DwarfAttribute[] = []): DwarfDie => ({
  offset, tag: 0x24, parentOffset: null, attributes
});

void test("DIE index resolves unit-relative and absolute references with parent links", async () => {
  const fixture = createDwarfSemanticFixture();
  const parsed = await analyzeDwarf(fixture.file, fixture.sections, true);

  const index = createDwarfDieIndex(parsed.units);

  assert.equal(resolveDwarfReference(index, index.records[2]!, reference(0x13,
    BigInt(fixture.typeOffset))), index.records[1]);
  assert.equal(resolveDwarfReference(index, index.records[3]!, reference(0x10,
    BigInt(fixture.typeOffset))), index.records[1]);
  assert.equal(index.children.get(index.records[2]!.die)?.[0], index.records[3]);
});

void test("references cannot escape their unit or target non-DIE bytes", () => {
  const index = createDwarfDieIndex([unit(0, [die(11)]), unit(100, [die(111)])]);
  const issues: string[] = [];
  index.records[0]!.die.attributes.push(reference(0x13, 111n));

  validateDwarfReferences(index, issues);

  assert.equal(resolveDwarfReference(index, index.records[0]!, undefined), null);
  assert.equal(resolveDwarfReference(index, index.records[0]!, reference(0x13, 111n)), null);
  assert.equal(resolveDwarfReference(index, index.records[0]!, reference(0x13, 12n)), null);
  assert.equal(resolveDwarfReference(index, index.records[0]!, reference(0x13, -1n)), null);
  assert.equal(resolveDwarfReference(index, index.records[0]!, reference(0x1c, 11n)), null);
  assert.match(issues.join(" "), /unresolved DIE reference/);
});

void test("signature references resolve the exact type DIE designated by the unit header", () => {
  const types = { ...unit(100, [die(123)]), sectionName: ".debug_types",
    typeSignature: 0x1234n, typeOffset: 23n };
  const index = createDwarfDieIndex([unit(0, [die(11)]), types]);

  assert.equal(resolveDwarfReference(index, index.records[0]!, reference(0x20, 0x1234n)),
    index.records[1]);
  assert.equal(resolveDwarfReference(index, index.records[0]!, reference(0x20, 0n)), null);
});

void test("inherited attributes retain the owning unit for further relative references", () => {
  const declared = die(111, [reference(0x13, 23n)]);
  const concrete = die(11, [{ ...reference(0x10, 111n), name: 0x47 }]);
  const index = createDwarfDieIndex([unit(0, [concrete]), unit(100, [declared, die(123)])]);

  const inherited = inheritedDwarfAttribute(index, index.records[0]!, 0x49);

  assert.equal(inherited?.record, index.records[1]);
  assert.equal(resolveDwarfReference(index, inherited!.record, inherited!.attribute), index.records[2]);
  assert.equal(inheritedDwarfAttribute(index, index.records[0]!, 0x03), undefined);
});

void test("attribute inheritance terminates and warns for cyclic origin/specification links", () => {
  const first = die(11, [{ ...reference(0x13, 12n), name: 0x31 }]);
  const second = die(12, [{ ...reference(0x13, 11n), name: 0x47 }]);
  const index = createDwarfDieIndex([unit(0, [first, second])]);
  const issues: string[] = [];

  validateDwarfReferences(index, issues);

  assert.equal(inheritedDwarfAttribute(index, index.records[0]!, 0x03), undefined);
  assert.match(issues.join(" "), /Cyclic/);
});
