import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { renderDwarfEntities } from "../../../../renderers/dwarf/entities.js";
import { createDwarfSemanticFixture } from "../../../fixtures/dwarf-semantic-fixture.js";

void test("entities show scoped parameters, resolved types, declarations, and frame locations", async () => {
  const fixture = createDwarfSemanticFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);

  const html = renderDwarfEntities(dwarf);

  assert.ok(html.includes("calculate::input"));
  assert.ok(html.includes("/project/src/main.c:7"));
  assert.ok(html.includes("<td>int</td>"));
  assert.ok(html.includes("frame base −8 bytes"));
  assert.ok(!html.includes("0x1000"));
  assert.ok(html.includes("<td class=\"dwarfTable__numeric\">6</td>"));
});

void test("entities escape names and make unresolved references visible", async () => {
  const fixture = createDwarfSemanticFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  dwarf.units[0]!.dies[2]!.attributes[0]!.value = { kind: "string", value: "<script>" };
  dwarf.units[0]!.dies[2]!.attributes[1]!.value = { kind: "unsigned", value: 999n };

  const html = renderDwarfEntities(dwarf);

  assert.ok(html.includes("&lt;script>"));
  assert.ok(html.includes("unresolved type"));
  assert.equal(renderDwarfEntities({ ...dwarf, units: [] }), "");
});

void test("entity details show enums, flags, blocks, resolved references, and variable lifetimes", async () => {
  const fixture = createDwarfSemanticFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const subprogram = dwarf.units[0]!.dies[2]!;
  subprogram.attributes.push(
    { name: 0x32, form: 0x0b, value: { kind: "unsigned", value: 3n } },
    { name: 0x3f, form: 0x0c, value: { kind: "flag", value: true } },
    { name: 0x3c, form: 0x0c, value: { kind: "flag", value: false } },
    { name: 0x1c, form: 0x0a, value: { kind: "block", value: Uint8Array.of(1, 2) } },
    { name: 0x1d, form: 0x13, value: { kind: "unsigned", value: BigInt(fixture.typeOffset) } },
    { name: 0x999, form: 0x17, value: { kind: "ranges", entries: [{ start: 0n, end: 2n }] } },
    { name: 0x02, form: 0x17, value: { kind: "locations", entries: [
      { range: null, operations: [{ offset: 0, opcode: 0x50, operands: [] }] },
      { range: { start: 0n, end: 4n }, operations: [{ offset: 0, opcode: 0x51, operands: [] }] }
    ] } },
    { name: 0x3b, form: 0x0f, value: { kind: "unsigned", value: 7n } },
    { name: 0x39, form: 0x0f, value: { kind: "unsigned", value: 2n } },
    { name: 0x18, form: 0x1c, value: { kind: "unsigned", value: 99n } }
  );

  const html = renderDwarfEntities(dwarf);

  assert.match(html, /private/);
  assert.ok(html.includes("<td>yes</td>"));
  assert.ok(html.includes("<td>no</td>"));
  assert.match(html, /2 bytes/);
  assert.match(html, /1 code ranges/);
  assert.match(html, /default location: DWARF register 0; 4 code bytes: DWARF register 1/);
  assert.match(html, /main.c:7:2/);
  assert.match(html, /unresolved DIE reference/);
});

void test("entities keep unnamed inline sites and omit empty attribute disclosures", async () => {
  const fixture = createDwarfSemanticFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const unit = dwarf.units[0]!;
  unit.dies.push({ offset: 99, parentOffset: unit.dies[2]!.offset, tag: 0x1d, attributes: [
    { name: 0x1c, form: 0x0f, value: { kind: "empty" } }
  ] });
  const subprogram = unit.dies[2]!;
  subprogram.attributes = [{ name: 0x03, form: 0x08, value: { kind: "string", value: "calculate" } }];

  const html = renderDwarfEntities(dwarf);

  assert.ok(html.includes("calculate::(unnamed)"));
  assert.match(html, /file not recorded/);
  assert.equal(html.match(/<details>/g)?.length, 2);
  dwarf.linePrograms = [];
  assert.match(renderDwarfEntities(dwarf), /file not recorded/);
});

void test("entities disclose declaration files that are absent from line tables", async () => {
  const fixture = createDwarfSemanticFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  dwarf.linePrograms[0]!.files = [];

  assert.match(renderDwarfEntities(dwarf), /unresolved file 1/);
  dwarf.linePrograms = [];
  assert.match(renderDwarfEntities(dwarf), /unresolved file 1/);
});
