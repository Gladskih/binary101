import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeDwarfDieExpressions } from "../../../../analyzers/dwarf/die-expressions.js";
import { createListUnit } from "../../../fixtures/dwarf-lists-fixture.js";

void test("DIE expressions distinguish legacy locations, exprloc, and ordinary block constants", async () => {
  const unit = createListUnit(4, [
    { name: 0x02, form: 0x0a, value: { kind: "block", value: Uint8Array.of(0x50) } },
    { name: 0x1c, form: 0x0a, value: { kind: "block", value: Uint8Array.of(0xff) } },
    { name: 0x1234, form: 0x18, value: { kind: "block", value: Uint8Array.of(0x03) } }
  ]);
  const issues: string[] = [];

  const decoded = await decodeDwarfDieExpressions([unit], "little", issues);

  assert.deepEqual(decoded[0]?.dies[0]?.attributes[0]?.value,
    { kind: "expression", operations: [{ offset: 0, opcode: 0x50, operands: [] }] });
  assert.deepEqual(decoded[0]?.dies[0]?.attributes[1]?.value, unit.dies[0]?.attributes[1]?.value);
  assert.equal(decoded[0]?.dies[0]?.attributes[2]?.value.kind, "expression");
  assert.match(issues.join(" "), /DIE.*Truncated/);
  assert.equal(unit.dies[0]?.attributes[0]?.value.kind, "block");
});
