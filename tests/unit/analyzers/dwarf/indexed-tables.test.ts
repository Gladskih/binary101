import assert from "node:assert/strict";
import { test } from "node:test";
import { DwarfIndexedReader } from "../../../../analyzers/dwarf/indexed-tables.js";
import { createDwarfSectionFile } from "../../../fixtures/dwarf-semantic-fixture.js";
import {
  concatenateBytes, encodeDwarf32Unit, encodeUint16, encodeUint8, encodeUint32, encodeUint64
} from "../../../fixtures/dwarf-fixture-encoding.js";
import { createDwarfListReader, createListUnit, encodeListContribution, listAttribute } from "../../../fixtures/dwarf-lists-fixture.js";
import type { DwarfUnit } from "../../../../analyzers/dwarf/types.js";

const unit: DwarfUnit = {
  sectionName: ".debug_info", offset: 0, length: 0n, format: 32, version: 5, unitType: 1,
  addressSize: 8, abbreviationOffset: 0n, dies: [{ offset: 12, tag: 0x11, parentOffset: null,
    attributes: [{ name: 0x73, form: 0x17, value: { kind: "unsigned", value: 8n } }] }]
}; // DW_AT_addr_base points after the DWARF32 address contribution header (7.27).

const readerFor = (bytes: number[], issues: string[]) => {
  const fixture = createDwarfSectionFile([{ name: ".debug_addr", bytes }]);
  return new DwarfIndexedReader(new Map(fixture.sections.map(section => [section.name, {
    summary: section, section, reader: fixture.file, decoded: true
  }])), "little", issues);
};

const addressContribution = (address: bigint) => encodeDwarf32Unit(concatenateBytes(
  encodeUint16(5), encodeUint8(8), encodeUint8(0), encodeUint64(address)
));

void test("address indices stay inside their contribution instead of reading the next header", async () => {
  const issues: string[] = [];
  const reader = readerFor(concatenateBytes(addressContribution(0x1000n), addressContribution(0x2000n)), issues);

  assert.equal(await reader.address(unit, 0n), 0x1000n);
  assert.equal(await reader.address(unit, 1n), null);
  assert.match(issues.join(" "), /outside.*contribution/);
});

void test("indexed tables warn for reserved lengths, truncated headers, and segmented addresses", async () => {
  const reserved: string[] = [];
  const truncated: string[] = [];
  const segmented: string[] = [];

  await readerFor(encodeUint32(0xfffffff0), reserved).address(unit, 0n);
  await readerFor([1], truncated).address(unit, 0n);
  await readerFor(encodeDwarf32Unit(concatenateBytes(
    encodeUint16(5), encodeUint8(8), encodeUint8(1)
  )), segmented).address(unit, 0n);

  assert.match(reserved.join(" "), /reserved initial length/);
  assert.match(truncated.join(" "), /Truncated/);
  assert.match(segmented.join(" "), /Segmented/);
});

void test("indexed readers reject absent bases, negative indices, and address-size mismatches", async () => {
  const issues: string[] = [];
  const reader = readerFor(addressContribution(7n), issues);

  assert.equal(await reader.address(createListUnit(5), 0n), null);
  assert.equal(await reader.address(unit, -1n), null);
  assert.equal(await reader.address({ ...unit, addressSize: 4 }, 0n), null);
  assert.equal(reader.cursor(".debug_addr", -1n), null);
  assert.equal(reader.cursor(".debug_addr", 999n), null);
  assert.match(issues.join(" "), /address-size mismatch/);
  assert.equal(await new DwarfIndexedReader(new Map(), "little", issues).address(unit, 0n), null);
});

void test("indexed lists reject references into headers and malformed offset tables", async () => {
  const issues: string[] = [];
  const reader = createDwarfListReader([{ name: ".debug_rnglists", bytes: encodeListContribution([0], [0]) }], issues);
  const based = createListUnit(5, [listAttribute(0x74, 0x17, 12n)]);

  assert.equal(await reader.listCursor(based, listAttribute(0x55, 0x23, 0n), ".debug_rnglists"), null);
  assert.equal(await reader.listCursor(createListUnit(5), listAttribute(0x55, 0x23, 0n), ".debug_rnglists"), null);
  assert.equal(await reader.listCursor(based, listAttribute(0x55, 0x17, 0n), ".debug_rnglists"), null);
  assert.equal(await reader.listCursor(based, { name: 0x55, form: 0x17, value: { kind: "flag", value: true } }, ".debug_rnglists"), null);
  assert.equal(await reader.listCursor({ ...based, addressSize: 4 }, listAttribute(0x55, 0x17, 16n), ".debug_rnglists"), null);
  assert.match(issues.join(" "), /outside.*payload/);
  const badCount = createDwarfListReader([{ name: ".debug_rnglists", bytes: encodeDwarf32Unit(
    concatenateBytes(encodeUint16(5), [8, 0], encodeUint32(2))
  ) }], issues);
  assert.equal(await badCount.listCursor(based, listAttribute(0x55, 0x23, 0n), ".debug_rnglists"), null);
  assert.match(issues.join(" "), /offset table extends/);
});

void test("string offsets validate contribution headers and support headerless legacy tables", async () => {
  const issues: string[] = [];
  const context = { version: 5, format: 32 as const, addressSize: 8, stringOffsetsBase: 8n };
  const invalid = createDwarfListReader([{ name: ".debug_str_offsets", bytes: encodeDwarf32Unit(
    concatenateBytes(encodeUint16(5), encodeUint16(1), encodeUint32(7))
  ) }], issues);
  const raw = createDwarfListReader([{ name: ".debug_str_offsets", bytes: encodeUint32(7) }], issues);

  assert.equal(await invalid.stringOffset(context, 0n), null);
  assert.match(issues.join(" "), /Invalid string offsets header/);
  assert.equal(await raw.stringOffset({ ...context, version: 4, stringOffsetsBase: 0n }, 0n), 7n);
  assert.equal(await raw.stringOffset({ ...context, version: 4, stringOffsetsBase: 0n }, 1n), null);
});
