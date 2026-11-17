import assert from "node:assert/strict";
import { after, test } from "node:test";
import * as iced from "iced-x86-disasm";
import { Amd64PrologMachine } from "../../../../../../analyzers/pe/exception/amd64/prolog-machine.js";
import { checkAmd64Epilog } from "../../../../../../analyzers/pe/exception/amd64/prolog-epilog.js";
import { prologDescription } from "../../../../../helpers/pe-prolog-fixture.js";

const factory = new iced.InstructionInfoFactory();
after(() => factory.free());
const machine = () => new Amd64PrologMachine(iced, factory);
const check = (state: Amd64PrologMachine, bytes: number[], description = prologDescription([], 0),
  end = 0x1100, offset = 0) =>
  checkAmd64Epilog(state, description, Uint8Array.from(bytes), 0x1000 + offset, 0x1000, end);

void test("recognizes a plain restored return and rejects an unbalanced one", () => {
  const state = machine();
  assert.equal(check(state, [0xc3]), "matching");
  state.values.set(iced.Register.RSP, { kind: "stack", offset: -8n });
  assert.equal(check(state, [0xc3]), "incomplete");
});

void test("recognizes immediate stack deallocation followed by a return", () => {
  const state = machine();
  state.values.set(iced.Register.RSP, { kind: "stack", offset: -40n });
  assert.equal(check(state, [0x48, 0x83, 0xc4, 0x28, 0xc3]), "matching");
  assert.equal(check(state, [0x48, 0x01, 0xc4, 0xc3]), "not-epilog");
});

void test("recognizes pops only when saved original values are available", () => {
  const state = machine();
  state.values.set(iced.Register.RSP, { kind: "stack", offset: -8n });
  state.values.set(iced.Register.RBX, { kind: "constant", offset: 0n });
  state.write(-8n, 8, { kind: "original", register: iced.Register.RBX });
  const description = prologDescription([{ opcode: "PUSH_NONVOL", codeOffset: 1, register: 3 }], 1);
  assert.equal(check(state, [0x5b, 0xc3], description, 0x1100, 1), "matching");
  assert.equal(check(state, [0x5d, 0xc3], description, 0x1100, 1), "incomplete");
  state.memory.clear();
  assert.equal(check(state, [0x5b, 0xc3], description, 0x1100, 1), "incomplete");
});

void test("recognizes frame-pointer restoration and reports an unknown frame", () => {
  const state = machine();
  state.values.set(iced.Register.RSP, { kind: "stack", offset: -48n });
  state.values.set(iced.Register.RBP, { kind: "stack", offset: -16n });
  state.write(-8n, 8, { kind: "original", register: iced.Register.RBP });
  const description = prologDescription([
    { opcode: "SET_FPREG", codeOffset: 1 }, { opcode: "PUSH_NONVOL", codeOffset: 1, register: 5 }
  ], 1, { frameRegister: 5 });
  assert.equal(check(state, [0x48, 0x8d, 0x65, 8, 0x5d, 0xc3], description), "matching");
  state.values.delete(iced.Register.RBP);
  assert.equal(check(state, [0x48, 0x8d, 0x65, 8, 0x5d, 0xc3], description), "incomplete");
});

for (const [bytes, expected] of [
  [[0xe9, 0xfb, 0, 0, 0], "matching"], // Near JMP to the exclusive end, 0x1100.
  [[0xe9, 0xf0, 0xff, 0xff, 0xff], "matching"],
  [[0xe9, 0, 0, 0, 0], "not-epilog"],
  [[0xff, 0x20], "not-epilog"], // The Windows implementation needs FF 25 or REX.W FF /4.
  [[0x48, 0xff, 0x20], "matching"],
  [[0x48, 0xff, 0xe0], "matching"],
  [[0xff, 0x25, 0, 0, 0, 0], "matching"],
  [[0xff, 0x24, 0x25, 0, 0, 0, 0], "not-epilog"],
  [[0xff, 0x60, 0], "not-epilog"], // ModRM.mod=01 remains forbidden with zero displacement.
  [[0xff, 0xa0, 0x80, 0, 0, 0], "not-epilog"],
  [[0xff, 0xe0], "not-epilog"],
  [[0x5c], "not-epilog"], [[0x66, 0x5b], "not-epilog"],
  [[0xc2, 8, 0], "matching"], [[0x90], "not-epilog"]
] as const) {
  void test(`classifies epilog transfer ${bytes.join(" ")}`, () => {
    assert.equal(check(machine(), [...bytes]), expected);
  });
}

void test("does not certify a return whose address could have been overwritten", () => {
  const state = machine();
  state.uncertainMemory = true;
  assert.equal(check(state, [0xc3]), "incomplete");
  state.uncertainMemory = false;
  state.write(0n, 8, { kind: "constant", offset: 0n });
  assert.equal(check(state, [0xc3]), "incomplete");
});

void test("does not require future inactive saves while checking an early epilog", () => {
  const state = machine();
  state.values.set(iced.Register.RBX, { kind: "constant", offset: 1n });
  const description = prologDescription([
    { opcode: "SAVE_NONVOL", codeOffset: 10, register: 3, displacement: 48 }
  ], 10);
  assert.equal(check(state, [0xc3], description), "matching");
});

void test("distinguishes exhausted lookahead from a function without a terminator", () => {
  const state = machine();
  state.values.set(iced.Register.RSP, { kind: "stack", offset: -8n });
  state.write(-8n, 8, { kind: "original", register: iced.Register.RBX });
  assert.equal(check(state, [0x5b]), "incomplete");
  assert.equal(check(state, [0x5b], prologDescription([], 0), 0x1001), "not-epilog");
  state.values.delete(iced.Register.RSP);
  assert.equal(check(state, [0xc3]), "incomplete");
});

void test("keeps a terminator crossing EndAddress unverified", () => {
  // Windows may decode the branch using bytes beyond the function range. The
  // bounded analyzer cannot certify it from this prefix alone.
  assert.equal(check(machine(), [0xe9, 0x1d], prologDescription([], 0), 0x1002), "incomplete");
});
