import assert from "node:assert/strict";
import { after, test } from "node:test";
import * as iced from "iced-x86-disasm";
import { Amd64PrologMachine } from "../../../../../../analyzers/pe/exception/amd64/prolog-machine.js";
import { checkAmd64PrologUnwind } from "../../../../../../analyzers/pe/exception/amd64/prolog-unwind.js";
import { prologDescription } from "../../../../../helpers/pe-prolog-fixture.js";

const factory = new iced.InstructionInfoFactory();
const instruction = new iced.Instruction();
after(() => { instruction.free(); factory.free(); });

void test("restores an entire XMM save, including a wider store's low 128-bit lanes", () => {
  const machine = new Amd64PrologMachine(iced, factory);
  machine.write(16n, 32, { kind: "original", register: iced.Register.ZMM6 });
  const result = checkAmd64PrologUnwind(machine, prologDescription([
    { opcode: "SAVE_XMM128", register: 6, displacement: 16, codeOffset: 1 }
  ], 1), 1, instruction);
  assert.deepEqual(result, { issues: [], limitations: [] });
});

void test("does not equate a narrow store with a full XMM save", () => {
  const machine = new Amd64PrologMachine(iced, factory);
  machine.write(16n, 8, { kind: "original", register: iced.Register.ZMM6 });
  const result = checkAmd64PrologUnwind(machine, prologDescription([
    { opcode: "SAVE_XMM128_FAR", register: 6, displacement: 16, codeOffset: 1 }
  ], 1), 1, instruction);
  assert.equal(result.issues[0]?.expected, "recover XMM6");
});

void test("keeps opaque saved values and possible memory aliases unverified", () => {
  const machine = new Amd64PrologMachine(iced, factory);
  machine.uncertainMemory = true;
  machine.write(16n, 8, undefined);
  const result = checkAmd64PrologUnwind(machine, prologDescription([
    { opcode: "SAVE_NONVOL_FAR", register: 3, displacement: 16, codeOffset: 1 },
    { opcode: "SAVE_NONVOL", register: 5, displacement: 32, codeOffset: 1 }
  ], 1), 1, instruction);
  assert.deepEqual(result.issues, []);
  assert.ok(result.limitations.includes("unknown-saved-value"));
  assert.ok(result.limitations.includes("unknown-register-value"));
});

void test("does not invent a frame base when the frame register is unknown", () => {
  const machine = new Amd64PrologMachine(iced, factory);
  machine.values.delete(iced.Register.RBP);
  const result = checkAmd64PrologUnwind(machine, prologDescription([
    { opcode: "SET_FPREG", codeOffset: 1 }
  ], 1, { frameRegister: 5 }), 1, instruction);
  assert.deepEqual(result.limitations, ["unknown-stack-effect"]);
});

void test("does not invent a save inside a larger unknown call-clobbered region", () => {
  const machine = new Amd64PrologMachine(iced, factory);
  machine.write(-8n, 40, undefined);
  const result = checkAmd64PrologUnwind(machine, prologDescription([
    { opcode: "SAVE_NONVOL", register: 3, displacement: 8, codeOffset: 1 }
  ], 1), 1, instruction);
  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.limitations, ["unknown-register-value"]);
});

void test("requires an actual save between adjacent unknown memory regions", () => {
  const machine = new Amd64PrologMachine(iced, factory);
  machine.write(0n, 8, undefined);
  machine.write(16n, 8, undefined);
  const result = checkAmd64PrologUnwind(machine, prologDescription([
    { opcode: "SAVE_NONVOL", register: 3, displacement: 8, codeOffset: 1 }
  ], 1), 1, instruction);
  assert.equal(result.issues[0]?.expected, "recover RBX");
  assert.deepEqual(result.limitations, []);
});
