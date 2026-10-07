import assert from "node:assert/strict";
import { test } from "node:test";
import { readDwarfMacroEntry } from "../../../../analyzers/dwarf/macro-entries.js";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";
import { DwarfStringReader } from "../../../../analyzers/dwarf/strings.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";
import { concatenateBytes, encodeCString, encodeUint32 } from "../../../fixtures/dwarf-fixture-encoding.js";

const readEntry = async (bytes: number[], issues: string[] = [], descriptors = new Map<number, number[]>(),
  version: number | null = 5) => {
  const sections = dwarfMacroSources([{ name: ".debug_macro", bytes },
    { name: ".debug_str", bytes: encodeCString("SHARED 1") }]);
  const source = sections.get(".debug_macro")!;
  return readDwarfMacroEntry(new DwarfCursor(source.reader, source.section, 0, bytes.length, true, issues),
    { version, format: 32, lineOffset: null, operandForms: descriptors },
    new DwarfStringReader(sections, "little", issues));
};

void test("macro entry layouts decode extensions and retain unresolved supplementary/indexed text", async () => {
  assert.deepEqual(await readEntry(concatenateBytes([224], encodeCString("extension"), [7]), [],
    new Map([[224, [8, 15]]])), { offset: 0, opcode: 224,
    operands: [{ kind: "string", value: "extension" }, { kind: "unsigned", value: 7n }] });
  assert.deepEqual(await readEntry([12, 1, 2]), { offset: 0, opcode: 12,
    operands: [{ kind: "unsigned", value: 1n }, { kind: "string-index", value: 2n }] });
  const issues: string[] = [];
  assert.deepEqual(await readEntry(concatenateBytes([9, 1], encodeUint32(7)), issues), {
    offset: 0, opcode: 9, operands: [{ kind: "unsigned", value: 1n },
      { kind: "string-offset", value: 7n, sectionName: "supplementary .debug_str" }]
  });
  assert.match(issues.join(" "), /supplementary.*required/);
  assert.equal(await readEntry([0]), "end");
});

void test("macro entries validate custom standard descriptors and legacy opcode boundaries", async () => {
  const issues: string[] = [];

  assert.equal(await readEntry([1, 0], issues, new Map([[1, [15, 15]]])), null);
  assert.equal(await readEntry([5, 0], issues, new Map(), null), null);
  assert.equal(await readEntry([224, 0x80], issues, new Map([[224, [15]]])), null);
  assert.equal(await readEntry([], issues), null);
  assert.deepEqual(await readEntry(concatenateBytes([1, 0], encodeCString("ok")), issues,
    new Map([[1, [15, 8]]])), { offset: 0, opcode: 1,
    operands: [{ kind: "unsigned", value: 0n }, { kind: "string", value: "ok" }] });
  assert.match(issues.join(" "), /disagrees/);
  assert.match(issues.join(" "), /legacy macro opcode/);
});
