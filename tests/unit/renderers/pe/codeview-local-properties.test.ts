import assert from "node:assert/strict";
import { test } from "node:test";
import { codeViewFrameBase, codeViewFrameFlags, codeViewLocalFlags,
  codeViewLocalPlacement, codeViewLocalRegister } from "../../../../renderers/pe/codeview-local-properties.js";

void test("CodeView local/frame flags retain known meanings and unknown bits", () => {
  assert.equal(codeViewLocalFlags(undefined), "not stored");
  assert.equal(codeViewLocalFlags(0), "none");
  assert.equal(codeViewLocalFlags(0x101), "parameter, optimized out");
  assert.equal(codeViewLocalFlags(0x8000), "unknown bits 0x8000");
  assert.equal(codeViewFrameFlags(0x154000), "PGO, optimized for speed");
  assert.equal(codeViewFrameFlags(0x80000000), "unknown bits 0x80000000");
});

void test("CodeView frame bases depend on the PE CPU rather than generic register numbers", () => {
  assert.equal(codeViewFrameBase(1, 0x8664), "RSP");
  assert.equal(codeViewFrameBase(2, 0x14c), "EBP");
  assert.equal(codeViewFrameBase(3, 0x1c4), "reserved");
  assert.equal(codeViewFrameBase(2, 0x1c4), "R7");
  assert.match(codeViewFrameBase(1, 0xaa64), /architecture mapping unavailable/);
  assert.match(codeViewFrameBase(4, 0x8664), /encoded base 4/);
});

void test("CodeView register names never cross CPU namespaces", () => {
  assert.equal(codeViewLocalRegister(328, 0x8664), "RAX");
  assert.equal(codeViewLocalRegister(343, 0x8664), "R15");
  assert.equal(codeViewLocalRegister(22, 0x14c), "EBP");
  assert.equal(codeViewLocalRegister(17, 0x14c), "EAX");
  assert.equal(codeViewLocalRegister(17, 0x1c4), "R7");
  assert.equal(codeViewLocalRegister(23, 0x1c4), "SP");
  assert.equal(codeViewLocalRegister(25, 0x1c4), "PC");
  assert.equal(codeViewLocalRegister(9, 0x1c4), "CodeView register #9");
  assert.equal(codeViewLocalRegister(328, undefined), "CodeView register #328");
});

void test("CodeView location descriptions keep signed displacements and unevaluated programs explicit", () => {
  assert.equal(codeViewLocalPlacement({ kind: "frameRelative", offset: -8 }, 0x8664), "frame base - 8");
  assert.equal(codeViewLocalPlacement({ kind: "registerRelative", offset: 16, register: 335 }, 0x8664), "RSP + 16");
  assert.equal(codeViewLocalPlacement({ kind: "register", register: 330 }, 0x8664), "RCX");
  assert.equal(codeViewLocalPlacement({ kind: "program", program: 42 }, undefined), "DIA program #42 (not evaluated)");
  assert.equal(codeViewLocalPlacement({ kind: "registerOffset", register: 334, offset: 4294967288 }, 0x8664),
    "RBP + stored unsigned offset 4294967288");
});

void test("Multi-register, IL slot and DPC groupshared placements retain distinct storage semantics", () => {
  assert.equal(codeViewLocalPlacement({ kind: "registers", registers: [328, 329] }, 0x8664),
    "RAX, RBX (most significant first)");
  assert.equal(codeViewLocalPlacement({ kind: "registers", registers: [] }, undefined), "empty register list");
  assert.equal(codeViewLocalPlacement({ kind: "slot", slot: 7 }, undefined), "IL slot #7");
  assert.equal(codeViewLocalPlacement({ kind: "groupShared", slot: 7, offset: 0xffff }, undefined),
    "DPC groupshared slot #7 + byte offset 65535");
});

void test("Shader locations expose raw register types, memory spaces and incomplete offsets", () => {
  assert.equal(codeViewLocalPlacement({ kind: "shaderRegister", registerType: 3, attributes: 0x16,
    registerOffsets: [0xffffffff, 9] }, undefined),
  "HLSL indexable temporary register type #3; memory space #2; register offsets [4294967295, 9]; spilled member");
  assert.equal(codeViewLocalPlacement({ kind: "shaderRegister", registerType: 0xffff, attributes: 0x83 }, undefined),
    "HLSL unknown register type #65535; memory space #0; register offsets unavailable (3 dimensions); unknown attributes 0x80");
  assert.equal(codeViewLocalPlacement({ kind: "shaderRegister", registerType: 0, attributes: 0,
    registerOffsets: [] }, undefined), "HLSL temporary register type #0; memory space #0; register offsets []");
});

void test("Indirect locations describe dereferencing and retain stored displacement signedness", () => {
  assert.equal(codeViewLocalPlacement({ kind: "registerIndirectOffset", register: 334,
    offset: 0xffffffff, memberOffset: 0x80000000 }, 0x8664),
  "dereference(RBP + stored unsigned offset 4294967295) + stored unsigned member offset 2147483648 (not evaluated)");
  assert.equal(codeViewLocalPlacement({ kind: "registerIndirectRelative", register: 334,
    offset: -8, memberOffset: -16 }, 0x8664), "dereference(RBP - 8) - 16 (not evaluated)");
  assert.equal(codeViewLocalPlacement({ kind: "registerIndirectRelative", register: 334,
    offset: 0, memberOffset: 16 }, undefined), "dereference(CodeView register #334 + 0) + 16 (not evaluated)");
});
