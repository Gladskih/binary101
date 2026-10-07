import assert from "node:assert/strict";
import { test } from "node:test";
import { readDwarfMacroHeader } from "../../../../analyzers/dwarf/macro-header.js";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { concatenateBytes, encodeUint64 } from "../../../fixtures/dwarf-fixture-encoding.js";

const readHeader = async (bytes: number[], issues: string[] = [], name = ".debug_macro") => {
  const file = new MockFile(Uint8Array.from(bytes));
  return readDwarfMacroHeader(new DwarfCursor(file,
    { name, offset: 0, size: bytes.length, compressed: false }, 0, bytes.length, true, issues), name);
};

void test("macro headers read DWARF64 line offsets and custom operand descriptors", async () => {
  const header = await readHeader(concatenateBytes([5, 0, 7], encodeUint64(99), [1, 224, 2, 8, 15]));

  assert.equal(header?.format, 64);
  assert.equal(header?.lineOffset, 99n);
  assert.deepEqual(header?.operandForms, new Map([[224, [8, 15]]]));
  assert.equal((await readHeader([4, 0, 0]))?.version, 4);
  assert.equal((await readHeader([], [], ".debug_macinfo"))?.version, null);
});

const invalid = [
  { name: "descriptor count", bytes: [5, 0, 4] },
  { name: "opcode", bytes: [5, 0, 4, 1] },
  { name: "zero opcode", bytes: [5, 0, 4, 1, 0] },
  { name: "operand count", bytes: [5, 0, 4, 1, 224] },
  { name: "oversized operand count", bytes: [5, 0, 4, 1, 224, 9] },
  { name: "unallowed form", bytes: [5, 0, 4, 1, 224, 1, 1] },
  { name: "duplicate opcode", bytes: [5, 0, 4, 2, 224, 0, 224, 0] },
  { name: "line offset", bytes: [5, 0, 2, 0] }
];
for (const example of invalid) {
  void test(`macro headers reject malformed ${example.name}`, async () => {
    const issues: string[] = [];

    assert.equal(await readHeader(example.bytes, issues), null);
    assert.ok(issues.length > 0);
  });
}
