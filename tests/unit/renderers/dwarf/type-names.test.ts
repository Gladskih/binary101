import assert from "node:assert/strict";
import { test } from "node:test";
import { dwarfTypeName } from "../../../../renderers/dwarf/type-names.js";
import { createDwarfDieIndex } from "../../../../analyzers/dwarf/references.js";
import type { DwarfDie } from "../../../../analyzers/dwarf/types.js";
import { createListUnit, listAttribute } from "../../../fixtures/dwarf-lists-fixture.js";

const typeDie = (offset: number, tag: number, target?: number): DwarfDie => ({
  offset, tag, parentOffset: 12, attributes: target == null ? [] : [listAttribute(0x49, 0x13, BigInt(target))]
});
const named = (offset: number, name: string): DwarfDie => ({ ...typeDie(offset, 0x24), attributes: [
  { name: 0x03, form: 0x08, value: { kind: "string", value: name } }
] });
const indexFor = (dies: DwarfDie[]) => createDwarfDieIndex([{ ...createListUnit(4), dies }]);

void test("type names distinguish a const pointer from a pointer to const data", () => {
  const index = indexFor([named(20, "int"), typeDie(30, 0x26, 20), typeDie(40, 0x0f, 30),
    typeDie(50, 0x0f, 20), typeDie(60, 0x26, 50)]);

  assert.equal(dwarfTypeName(index, index.records[2]!), "pointer to const int");
  assert.equal(dwarfTypeName(index, index.records[4]!), "const pointer to int");
});

void test("type names show array counts and explicit bounds without guessing missing bounds", () => {
  const array = typeDie(30, 0x01, 20);
  const count = { ...typeDie(40, 0x21), parentOffset: 30, attributes: [listAttribute(0x37, 0x0f, 3n)] };
  const bounds = { ...typeDie(50, 0x21), parentOffset: 30, attributes: [
    listAttribute(0x22, 0x0d, -2n), listAttribute(0x2f, 0x0f, 2n)
  ] };
  const unknown = { ...typeDie(60, 0x21), parentOffset: 30 };
  const index = indexFor([named(20, "int"), array, count, bounds, unknown]);

  assert.equal(dwarfTypeName(index, index.records[1]!), "array [3][-2…2][] of int");
  assert.equal(dwarfTypeName(indexFor([array]), { unit: createListUnit(4), die: array }),
    "array [] of unresolved type");
});

void test("type names preserve unknown, void, unresolved, and recursive type distinctions", () => {
  const index = indexFor([typeDie(20, 0x0f), typeDie(30, 0x0f, 999), typeDie(40, 0x0f, 40),
    typeDie(50, 0x7777), typeDie(60, 0x10, 20), typeDie(70, 0x42, 20)]);

  assert.equal(dwarfTypeName(index, null), "unspecified type");
  assert.equal(dwarfTypeName(index, index.records[0]!), "pointer to void");
  assert.equal(dwarfTypeName(index, index.records[1]!), "pointer to unresolved type");
  assert.equal(dwarfTypeName(index, index.records[2]!), "pointer to recursive type");
  assert.equal(dwarfTypeName(index, index.records[3]!), "DW TAG 0x7777");
  assert.equal(dwarfTypeName(index, index.records[4]!), "reference to pointer to void");
  assert.equal(dwarfTypeName(index, index.records[5]!), "rvalue reference to pointer to void");
});
