import assert from "node:assert/strict";
import { test } from "node:test";
import { armPrel31, readArmEhabiProgram } from "../../../../analyzers/elf/arm-ehabi-program.js";
import type { ArmEhabiEntry } from "../../../../analyzers/elf/arm-ehabi-types.js";
import { lsdaFixture } from "../../../fixtures/elf-lsda.js";

const entry = (): ArmEhabiEntry => ({ offset: 0, functionAddress: 0n, tableAddress: 4096n,
  data: 0, instructions: [], issues: [] });

void test("sign-extends PREL31 and wraps 32-bit addresses", () => {
  assert.equal(armPrel31(0x7ffffffc, 4096n), 4092n);
  assert.equal(armPrel31(4, 0xfffffffcn), 0n);
  assert.equal(armPrel31(0x7ffffffc, 0n), 0xfffffffcn);
});

void test("retains generic personality pointers and rejects invalid inline formats", async () => {
  const generic = entry();
  await readArmEhabiProgram(4, lsdaFixture([]).cursorAt(0), generic);
  assert.equal(generic.personality, 4100n);
  assert.match(generic.issues.join(" "), /Generic/);
  const inline = entry();
  await readArmEhabiProgram(0x8100b0b0, null, inline);
  assert.match(inline.issues.join(" "), /Inline/);
  const reserved = entry();
  await readArmEhabiProgram(0x9000b0b0, null, reserved);
  assert.match(reserved.issues.join(" "), /Reserved/);
});

void test("does not decode partially truncated long programs", async () => {
  const source = lsdaFixture([1, 2]);
  const parsed = entry();
  await readArmEhabiProgram(0x8201b0b0, source.cursorAt(0), parsed);
  assert.deepEqual(parsed.instructions, []);
  assert.match(source.result.issues.join(" "), /Truncated/);
});
