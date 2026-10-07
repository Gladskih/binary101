import assert from "node:assert/strict";
import { test } from "node:test";
import { readDwarfRangeList } from "../../../../analyzers/dwarf/range-lists.js";
import {
  createListUnit, listAttribute, createDwarfListReader, encodeListContribution, encodeAddressContribution
} from "../../../fixtures/dwarf-lists-fixture.js";
import { concatenateBytes, encodeUint64, encodeUleb } from "../../../fixtures/dwarf-fixture-encoding.js";

// Independent range list opcodes and attribute/form codes: DWARF 5 Tables 7.30/7.17/7.5.
void test("legacy range lists apply base selections and retain every range", async () => {
  const issues: string[] = [];
  const reader = createDwarfListReader([{ name: ".debug_ranges", bytes: concatenateBytes(
    encodeUint64(0xffffffffffffffffn), encodeUint64(0x1000),
    encodeUint64(2), encodeUint64(6), encodeUint64(0), encodeUint64(0)
  ) }], issues);

  const ranges = await readDwarfRangeList(reader, createListUnit(4), listAttribute(0x55, 0x17, 0n));

  assert.deepEqual(ranges, [{ start: 0x1002n, end: 0x1006n }]);
  assert.deepEqual(issues, []);
});

void test("DWARF 5 range lists decode all bounded entry encodings and indexed bases", async () => {
  const issues: string[] = [];
  const reader = createDwarfListReader([
    { name: ".debug_addr", bytes: encodeAddressContribution([0x1000n, 0x1008n]) },
    { name: ".debug_rnglists", bytes: encodeListContribution(concatenateBytes(
      [1], encodeUleb(0), [4], encodeUleb(2), encodeUleb(4),
      [2], encodeUleb(0), encodeUleb(1), [3], encodeUleb(1), encodeUleb(3),
      [5], encodeUint64(0x2000), [4], encodeUleb(1), encodeUleb(2),
      [6], encodeUint64(0x3000), encodeUint64(0x3005),
      [7], encodeUint64(0x4000), encodeUleb(2), [0]
    ), [4]) }
  ], issues);
  const unit = createListUnit(5, [listAttribute(0x73, 0x17, 8n), listAttribute(0x74, 0x17, 12n)]);

  const ranges = await readDwarfRangeList(reader, unit, listAttribute(0x55, 0x23, 0n));

  assert.deepEqual(ranges, [
    { start: 0x1002n, end: 0x1004n }, { start: 0x1000n, end: 0x1008n },
    { start: 0x1008n, end: 0x100bn }, { start: 0x2001n, end: 0x2002n },
    { start: 0x3000n, end: 0x3005n }, { start: 0x4000n, end: 0x4002n }
  ]);
  assert.deepEqual(issues, []);
});

void test("range lists reject reversed ranges and warn on missing terminators", async () => {
  const issues: string[] = [];
  const reader = createDwarfListReader([{ name: ".debug_ranges", bytes: concatenateBytes(
    encodeUint64(5), encodeUint64(2)
  ) }], issues);

  assert.deepEqual(await readDwarfRangeList(reader, createListUnit(4), listAttribute(0x55, 0x17, 0n)), []);
  assert.match(issues.join(" "), /before its start/);
  assert.match(issues.join(" "), /no end-of-list/);
  assert.equal(issues.length, 2);
});

void test("range lists reject missing sections, invalid indexes, and unknown entries", async () => {
  const issues: string[] = [];
  const reader = createDwarfListReader([{ name: ".debug_rnglists", bytes: encodeListContribution([0xff], [4]) }], issues);
  const unit = createListUnit(5, [listAttribute(0x74, 0x17, 12n)]);

  assert.equal(await readDwarfRangeList(reader, createListUnit(4), listAttribute(0x55, 0x17, 0n)), null);
  assert.equal(await readDwarfRangeList(reader, unit, listAttribute(0x55, 0x23, 1n)), null);
  assert.deepEqual(await readDwarfRangeList(reader, unit, listAttribute(0x55, 0x17, 16n)), []);
  assert.match(issues.join(" "), /outside/);
  assert.match(issues.join(" "), /Unknown range-list entry/);
});

void test("split range lists retain unavailable ranges when the skeleton address table is absent", async () => {
  const issues: string[] = [];
  const reader = createDwarfListReader([{ name: ".debug_rnglists", bytes: encodeListContribution([3, 0, 2, 0]) }], issues);
  const split = { ...createListUnit(5), sectionName: ".debug_info.dwo" };
  const ranges = await readDwarfRangeList(reader, split, listAttribute(0x55, 0x17, 12n));
  assert.deepEqual(ranges, [{ kind: "unresolved" }]);
  assert.match(issues.join(" "), /indexed address or base is unavailable/);
});
