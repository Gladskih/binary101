import assert from "node:assert/strict";
import { test } from "node:test";
import {
  advanceDwarfLineAddress, createDwarfLineRegisters, emitDwarfLineRow
} from "../../../../analyzers/dwarf/line-registers.js";
import { createDwarfLineMachine } from "../../../fixtures/dwarf-line-machine-fixture.js";

void test("line registers model VLIW operation indexes and independent emitted rows", async () => {
  const machine = await createDwarfLineMachine();
  machine.header.maximumOperationsPerInstruction = 3;
  machine.header.minimumInstructionLength = 4;
  machine.state.basicBlock = true;
  machine.state.prologueEnd = true;
  machine.state.epilogueBegin = true;
  machine.state.discriminator = 7n;

  advanceDwarfLineAddress(machine.state, machine.header, 7n);
  emitDwarfLineRow(machine.rows, machine.state);
  advanceDwarfLineAddress(machine.state, machine.header, 2n);

  assert.equal(machine.rows[0]?.address, 8n);
  assert.equal(machine.rows[0]?.operationIndex, 1n);
  assert.equal(machine.rows[0]?.basicBlock, true);
  assert.equal(machine.state.address, 12n);
  assert.equal(machine.state.operationIndex, 0n);
  assert.equal(machine.state.basicBlock, false);
  assert.equal(machine.state.prologueEnd, false);
  assert.equal(machine.state.epilogueBegin, false);
  assert.equal(machine.state.discriminator, 0n);
  assert.equal(createDwarfLineRegisters(machine.header).file, 1n);
});
