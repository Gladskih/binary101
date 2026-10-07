import assert from "node:assert/strict";
import { test } from "node:test";
import { linkDwarfMacros } from "../../../../analyzers/dwarf/macro-links.js";
import { DwarfStringReader } from "../../../../analyzers/dwarf/strings.js";
import type { DwarfMacroUnit } from "../../../../analyzers/dwarf/macro-types.js";
import { createListUnit, listAttribute } from "../../../fixtures/dwarf-lists-fixture.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";
import { concatenateBytes, encodeCString, encodeDwarf32Unit, encodeUint16, encodeUint32 } from "../../../fixtures/dwarf-fixture-encoding.js";

const indexedMacro = (offset: number): DwarfMacroUnit => ({
  sectionName: ".debug_macro", offset, version: 5, format: 32, lineOffset: null,
  entries: [{ offset: offset + 3, opcode: 11, operands: [
    { kind: "unsigned", value: 1n }, { kind: "string-index", value: 0n }
  ] }]
});
const stringReader = (issues: string[]) => new DwarfStringReader(dwarfMacroSources([
  { name: ".debug_str_offsets", bytes: encodeDwarf32Unit(concatenateBytes(
    encodeUint16(5), encodeUint16(0), encodeUint32(0))) },
  { name: ".debug_str", bytes: encodeCString("INDEXED 1") }
]), "little", issues);

void test("indexed macro strings inherit the importing CU's string table context", async () => {
  const issues: string[] = [];
  const macro = indexedMacro(9);
  const importing: DwarfMacroUnit = { ...indexedMacro(0), entries: [
    { offset: 3, opcode: 7, operands: [{ kind: "unsigned", value: 9n }] }
  ] };
  const unit = createListUnit(5, [listAttribute(0x79, 0x17, 0n), listAttribute(0x72, 0x17, 8n)]);

  await linkDwarfMacros([importing, macro], [unit], stringReader(issues), issues);

  assert.deepEqual(macro.entries[0]?.operands[1], { kind: "string", value: "INDEXED 1" });
  assert.deepEqual(issues, []);
});

void test("macro string indices preserve unresolved values for conflicting or missing CU contexts", async () => {
  const issues: string[] = [];
  const macro = indexedMacro(0);
  const owner = createListUnit(5, [listAttribute(0x79, 0x17, 0n), listAttribute(0x72, 0x17, 8n)]);
  const conflicting = createListUnit(5, [listAttribute(0x79, 0x17, 0n), listAttribute(0x72, 0x17, 99n)]);

  await linkDwarfMacros([macro], [owner, conflicting], stringReader(issues), issues);
  await linkDwarfMacros([macro], [], stringReader(issues), issues);
  assert.equal(macro.entries[0]?.operands[1]?.kind, "string-index");
  assert.equal(issues.length, 2);
  assert.match(issues.join(" "), /no unique importing unit/);
});

void test("macro owners support legacy/GNU attributes and warn on unresolved indexed strings", async () => {
  const issues: string[] = [];
  const legacy = { ...indexedMacro(0), version: null, sectionName: ".debug_macinfo" };
  const missing = indexedMacro(9);

  await linkDwarfMacros([legacy, missing], [
    createListUnit(5, [listAttribute(0x43, 0x17, 0n), listAttribute(0x72, 0x17, 8n)]),
    createListUnit(5, [listAttribute(0x2119, 0x17, 9n)])
  ], stringReader(issues), issues);

  assert.equal(legacy.entries[0]?.operands[1]?.kind, "string");
  assert.equal(missing.entries[0]?.operands[1]?.kind, "string-index");
  assert.match(issues.join(" "), /str_offsets_base/);
});
