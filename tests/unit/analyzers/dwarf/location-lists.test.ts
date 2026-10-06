import assert from "node:assert/strict";
import { test } from "node:test";
import { readDwarfLocationList } from "../../../../analyzers/dwarf/location-lists.js";
import {
  createListUnit, listAttribute, createDwarfListReader, encodeListContribution, encodeAddressContribution
} from "../../../fixtures/dwarf-lists-fixture.js";
import { concatenateBytes, encodeUint64, encodeUint16, encodeUleb } from "../../../fixtures/dwarf-fixture-encoding.js";

void test("legacy location lists decode base-relative lifetimes and register expressions", async () => {
  const issues: string[] = [];
  const reader = createDwarfListReader([{ name: ".debug_loc", bytes: concatenateBytes(
    encodeUint64(0xffffffffffffffffn), encodeUint64(0x1000),
    encodeUint64(0), encodeUint64(4), encodeUint16(1), [0x50],
    encodeUint64(0), encodeUint64(0)
  ) }], issues);

  const locations = await readDwarfLocationList(reader, createListUnit(4),
    listAttribute(0x02, 0x17, 0n), "little", issues);

  assert.deepEqual(locations, [{ range: { start: 0x1000n, end: 0x1004n },
    operations: [{ offset: 0, opcode: 0x50, operands: [] }] }]);
  assert.deepEqual(issues, []);
});

void test("DWARF 5 locations decode every range encoding and the default location", async () => {
  const issues: string[] = [];
  const reader = createDwarfListReader([
    { name: ".debug_addr", bytes: encodeAddressContribution([0x1000n, 0x1004n]) },
    { name: ".debug_loclists", bytes: encodeListContribution(concatenateBytes(
      [1], encodeUleb(0), [4, 0, 2, 1, 0x50], [2, 0, 1, 1, 0x51],
      [3, 1, 2, 1, 0x52], [5, 1, 0x53], [6], encodeUint64(0x2000),
      [7], encodeUint64(0x2000), encodeUint64(0x2004), [1, 0x54],
      [8], encodeUint64(0x3000), [2, 1, 0x55], [0]
    ), [4]) }
  ], issues);
  const unit = createListUnit(5, [listAttribute(0x73, 0x17, 8n), listAttribute(0x8c, 0x17, 12n)]);

  const locations = await readDwarfLocationList(reader, unit, listAttribute(0x02, 0x22, 0n), "little", issues);

  assert.deepEqual(locations?.map(entry => entry.range), [
    { start: 0x1000n, end: 0x1002n }, { start: 0x1000n, end: 0x1004n },
    { start: 0x1004n, end: 0x1006n }, null, { start: 0x2000n, end: 0x2004n },
    { start: 0x3000n, end: 0x3002n }
  ]);
  assert.deepEqual(locations?.map(entry => entry.operations[0]?.opcode), [0x50, 0x51, 0x52, 0x53, 0x54, 0x55]);
  assert.deepEqual(issues, []);
});

void test("location lists warn about truncated expressions and unknown entry encodings", async () => {
  const truncated: string[] = [];
  const unknown: string[] = [];
  const reader = createDwarfListReader([{ name: ".debug_loc", bytes: concatenateBytes(
    encodeUint64(0), encodeUint64(2), encodeUint16(2), [0x50]
  ) }], truncated);
  const modern = createDwarfListReader([{ name: ".debug_loclists", bytes: encodeListContribution([0xff]) }], unknown);

  assert.deepEqual(await readDwarfLocationList(reader, createListUnit(4),
    listAttribute(0x02, 0x17, 0n), "little", truncated), []);
  assert.deepEqual(await readDwarfLocationList(modern, createListUnit(5),
    listAttribute(0x02, 0x17, 12n), "little", unknown), []);
  assert.match(truncated.join(" "), /Truncated/);
  assert.match(unknown.join(" "), /Unknown location-list entry/);
});

void test("location lists inherit low_pc and reject reversed lifetime ranges", async () => {
  const issues: string[] = [];
  const reader = createDwarfListReader([{ name: ".debug_loc", bytes: concatenateBytes(
    encodeUint64(0), encodeUint64(4), encodeUint16(1), [0x50],
    encodeUint64(9), encodeUint64(8), encodeUint16(1), [0x51],
    encodeUint64(0), encodeUint64(0)
  ) }], issues);

  assert.deepEqual(await readDwarfLocationList(reader, createListUnit(4, [listAttribute(0x11, 0x01, 0x1000n)]),
    listAttribute(0x02, 0x17, 0n), "little", issues), [{ range: { start: 0x1000n, end: 0x1004n },
    operations: [{ offset: 0, opcode: 0x50, operands: [] }] }]);
  assert.match(issues.join(" "), /Range ends before its start/);
});

void test("an unterminated location list reports its missing terminator without reading past its end", async () => {
  const issues: string[] = [];
  const reader = createDwarfListReader([{ name: ".debug_loc", bytes: concatenateBytes(
    encodeUint64(0), encodeUint64(1), encodeUint16(1), [0x50]
  ) }], issues);

  assert.equal((await readDwarfLocationList(reader, createListUnit(4),
    listAttribute(0x02, 0x17, 0n), "little", issues))?.length, 1);
  assert.equal(issues.length, 1);
  assert.match(issues[0]!, /Location list has no end-of-list terminator/);
});
