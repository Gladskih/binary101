import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { createDwarfMacroFixture, dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";
import { readDwarfMacros } from "../../../../analyzers/dwarf/macros.js";
import { concatenateBytes, encodeCString, encodeUint16, encodeUint32 } from "../../../fixtures/dwarf-fixture-encoding.js";

void test("DWARF decodes macro definitions, removals, include boundaries, and shared strings", async () => {
  const fixture = createDwarfMacroFixture();

  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);

  assert.equal(dwarf.macros?.length, 1);
  assert.deepEqual(dwarf.macros?.[0]?.entries.map(entry => entry.opcode), [3, 1, 2, 5, 4]);
  assert.deepEqual(dwarf.macros?.[0]?.entries[1]?.operands, [
    { kind: "unsigned", value: 7n }, { kind: "string", value: "LIMIT 42" }
  ]);
  assert.equal(dwarf.macros?.[0]?.lineOffset, 0n);
  assert.deepEqual(dwarf.issues, []);
});

void test("legacy macinfo preserves vendor entries and separates terminated units", async () => {
  const sources = dwarfMacroSources([{ name: ".debug_macinfo", bytes: concatenateBytes(
    [1, 0], encodeCString("COMMAND 1"), [255, 7], encodeCString("vendor"), [0, 3, 1, 1, 4, 0]
  ) }]);
  const issues: string[] = [];

  const macros = await readDwarfMacros(sources, [], "little", issues);

  assert.equal(macros.length, 2);
  assert.equal(macros[0]?.version, null);
  assert.equal(macros[0]?.entries[1]?.operands[1]?.kind, "string");
  assert.deepEqual(issues, []);
});

void test("macro imports point to real unit boundaries and retain supplementary provenance", async () => {
  const sources = dwarfMacroSources([{ name: ".debug_macro", bytes: concatenateBytes(
    encodeUint16(5), [0, 7], encodeUint32(9), [0],
    encodeUint16(5), [0, 10], encodeUint32(0), [0]
  ) }]);
  const issues: string[] = [];

  const macros = await readDwarfMacros(sources, [], "little", issues);

  assert.equal(macros.length, 2);
  assert.deepEqual(macros[0]?.entries[0]?.operands, [{ kind: "unsigned", value: 9n }]);
  assert.match(issues.join(" "), /supplementary.*macro/i);
});

const invalid = [
  { name: "header", bytes: [5] },
  { name: "version", bytes: [6, 0, 0] },
  { name: "flags", bytes: [5, 0, 8] },
  { name: "unknown opcode", bytes: [5, 0, 0, 254] },
  { name: "definition", bytes: [5, 0, 0, 1, 1, 65] },
  { name: "include operands", bytes: [5, 0, 0, 3, 1] },
  { name: "unterminated unit", bytes: [5, 0, 0, 4] },
  { name: "missing include end", bytes: [5, 0, 0, 3, 1, 1, 0] },
  { name: "unexpected include end", bytes: [5, 0, 0, 4, 0] },
  { name: "import boundary", bytes: [5, 0, 0, 7, 1, 0, 0, 0, 0] },
  { name: "import cycle", bytes: [5, 0, 0, 7, 0, 0, 0, 0, 0] }
];
for (const example of invalid) {
  void test(`macro parsing reports invalid ${example.name}`, async () => {
    const issues: string[] = [];

    await readDwarfMacros(dwarfMacroSources([{ name: ".debug_macro", bytes: example.bytes }]),
      [], "little", issues);

    assert.ok(issues.length > 0);
  });
}
