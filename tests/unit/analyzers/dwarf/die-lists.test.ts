import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeDwarfDieLists } from "../../../../analyzers/dwarf/die-lists.js";
import { createDwarfSectionFile } from "../../../fixtures/dwarf-semantic-fixture.js";
import { createListUnit, listAttribute } from "../../../fixtures/dwarf-lists-fixture.js";
import { concatenateBytes, encodeUint16, encodeUint64 } from "../../../fixtures/dwarf-fixture-encoding.js";

void test("DIE lists resolve indexed addresses and reuse repeated range and location references", async () => {
  const fixture = createDwarfSectionFile([
    { name: ".debug_addr", bytes: encodeUint64(0x1000) },
    { name: ".debug_ranges", bytes: concatenateBytes(encodeUint64(0), encodeUint64(4),
      encodeUint64(0), encodeUint64(0)) },
    { name: ".debug_loc", bytes: concatenateBytes(encodeUint64(0), encodeUint64(4),
      encodeUint16(1), [0x50], encodeUint64(0), encodeUint64(0)) }
  ]);
  const unit = createListUnit(4, [listAttribute(0x73, 0x17, 0n),
    { name: 0x11, form: 0x1f01, value: { kind: "address-index", value: 0n } },
    listAttribute(0x55, 0x17, 0n), listAttribute(0x02, 0x17, 0n), listAttribute(0x40, 0x17, 0n)]);
  unit.dies.push({ ...unit.dies[0]!, offset: 20, parentOffset: 12 });
  const issues: string[] = [];

  const result = await decodeDwarfDieLists([unit], new Map(fixture.sections.map(section =>
    [section.name, { section, summary: section, reader: fixture.file, decoded: true }])), "little", issues);

  const attributes = result[0]!.dies[0]!.attributes;
  assert.deepEqual(attributes[1]?.value, { kind: "unsigned", value: 0x1000n });
  assert.deepEqual(attributes[2]?.value, { kind: "ranges", entries: [{ start: 0x1000n, end: 0x1004n }] });
  assert.equal(attributes[3]?.value.kind, "locations");
  assert.equal(attributes[4]?.value.kind, "locations");
  assert.equal(attributes[3]?.value, attributes[4]?.value);
  assert.equal(attributes[2]?.value, result[0]?.dies[1]?.attributes[2]?.value);
  assert.equal(unit.dies[0]?.attributes[1]?.value.kind, "address-index");
  assert.deepEqual(issues, []);
});

void test("DIE lists retain unresolved attributes and report missing referenced sections", async () => {
  const unit = createListUnit(5, [
    { name: 0x11, form: 0x1b, value: { kind: "address-index", value: 0n } },
    listAttribute(0x55, 0x17, 0n), listAttribute(0x02, 0x17, 0n),
    { name: 0x03, form: 0x08, value: { kind: "string", value: "unchanged" } }
  ]);
  const issues: string[] = [];

  const result = await decodeDwarfDieLists([unit], new Map(), "little", issues);

  assert.deepEqual(result, [unit]);
  assert.match(issues.join(" "), /addr_base/);
  assert.match(issues.join(" "), /debug_rnglists/);
  assert.match(issues.join(" "), /debug_loclists/);
});
