import assert from "node:assert/strict";
import { test } from "node:test";
import { executeDwarfStandardLineOpcode } from "../../../../analyzers/dwarf/line-opcodes.js";
import { createDwarfLineMachine } from "../../../fixtures/dwarf-line-machine-fixture.js";

void test("unknown standard line opcodes consume exactly the declared operands", async () => {
  const machine = await createDwarfLineMachine([0x80, 1, 2]);
  machine.header.standardOperandCounts[12] = 2; // Future opcode 13: two ULEB operands (6.2.4).

  assert.equal(await executeDwarfStandardLineOpcode(machine.cursor, machine.header,
    machine.state, machine.rows, 13), true);
  assert.equal(machine.cursor.position, 3);
  assert.match(machine.issues.join(" "), /Unknown standard line opcode 13/);
  assert.equal(await executeDwarfStandardLineOpcode(machine.cursor, machine.header,
    machine.state, machine.rows, 99), true);
});

const truncated = [
  { name: "advance pc", opcode: 2 }, { name: "advance line", opcode: 3 },
  { name: "set file", opcode: 4 }, { name: "fixed advance", opcode: 9 },
  { name: "unknown operands", opcode: 13 }
];
for (const example of truncated) {
  void test(`line opcodes reject truncated ${example.name}`, async () => {
    const machine = await createDwarfLineMachine([0x80]);
    machine.header.standardOperandCounts[12] = 1;

    assert.equal(await executeDwarfStandardLineOpcode(machine.cursor, machine.header,
      machine.state, machine.rows, example.opcode), false);
    assert.match(machine.issues.join(" "), /Truncated/);
  });
}
