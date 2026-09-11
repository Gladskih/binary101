import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeArmEhabiInstructions } from "../../../../analyzers/elf/arm-ehabi-opcodes.js";

void test("decodes EHABI stack adjustments, register masks and finish", () => {
  assert.deepEqual(decodeArmEhabiInstructions([0, 0x40, 0x91, 0xa9, 0xb0]).instructions
    .map(instruction => instruction.text), ["vsp += 4", "vsp -= 4", "vsp = r1", "pop {r4, r5, r14}", "finish"]);
  assert.deepEqual(decodeArmEhabiInstructions([0x80, 0x81, 0xb1, 3]).instructions
    .map(instruction => instruction.text), ["pop {r4, r11}", "pop {r0, r1}", "finish (implicit)"]);
});

void test("reports reserved and truncated opcodes and refuses zero register masks", () => {
  assert.match(decodeArmEhabiInstructions([0x80]).issues.join(" "), /truncated/);
  assert.match(decodeArmEhabiInstructions([0x9d]).issues.join(" "), /Reserved/);
  assert.equal(decodeArmEhabiInstructions([0x80, 0]).instructions[0]?.text, "refuse to unwind");
  assert.match(decodeArmEhabiInstructions([0xb1, 0x10]).issues.join(" "), /Reserved/);
});

void test("decodes large stack adjustments and VFP operations", () => {
  assert.equal(decodeArmEhabiInstructions([0xb2, 1]).instructions[0]?.text, "vsp += 520");
  assert.equal(decodeArmEhabiInstructions([0xb3, 0x21]).instructions[0]?.text, "pop {d2, d3} (FSTMFDX)");
  assert.equal(decodeArmEhabiInstructions([0xc8, 1]).instructions[0]?.text, "pop {d16, d17} (VPUSH)");
});
void test("decodes all extended register families and authentication instructions", () => {
  assert.deepEqual(decodeArmEhabiInstructions([0xb4, 0xb5, 0xb8, 0xc0, 0xc6, 0x12,
    0xc7, 3, 0xc9, 0x21, 0xd0, 0xb0]).instructions.map(item => item.text), [
    "pop return address authentication code", "use vsp as authentication modifier",
    "pop {d8} (FSTMFDX)", "pop {wR10}", "pop {wR1, wR2, wR3}", "pop {wCGR0, wCGR1}",
    "pop {d2, d3} (VPUSH)", "pop {d8} (VPUSH)", "finish"
  ]);
  assert.match(decodeArmEhabiInstructions([0xb3, 0xff]).issues.join(" "), /Reserved/);
  assert.match(decodeArmEhabiInstructions([0xb3]).issues.join(" "), /truncated/);
  assert.match(decodeArmEhabiInstructions([0xb1]).issues.join(" "), /truncated/);
  assert.match(decodeArmEhabiInstructions([0xb2]).issues.join(" "), /truncated/);
  assert.match(decodeArmEhabiInstructions([0xb2, 128, 128, 128, 128, 128]).issues.join(" "), /five bytes/);
  assert.match(decodeArmEhabiInstructions(new Array<number>(4097).fill(0)).issues.join(" "), /limit/);
});
