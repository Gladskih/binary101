import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeArm64UnwindOperation } from "../../../../../analyzers/pe/exception/arm64-unwind-operations.js";
import type { Arm64UnwindBody } from "../../../../../analyzers/pe/exception/arm64-unwind-types.js";

const saved = (registers: string[], displacement: number, addressing: "offset" | "preIndex"): Arm64UnwindBody =>
  ({ kind: "save", registers, displacement, addressing, unit: "bytes" });

// Independent operand vectors from Microsoft's ARM64 "Unwind codes" table.
// https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling#unwind-codes
const vectors: [number[], string, Arm64UnwindBody][] = [
  [[0x20], "save_r19r20_x", saved(["X19", "X20"], -0, "preIndex")],
  [[0x40], "save_fplr", saved(["X29", "LR"], 0, "offset")],
  [[0x80], "save_fplr_x", saved(["X29", "LR"], -8, "preIndex")],
  [[0x1f], "alloc_s", { kind: "allocate", amount: 496, unit: "bytes" }],
  [[0x3f], "save_r19r20_x", saved(["X19", "X20"], -248, "preIndex")],
  [[0x7f], "save_fplr", saved(["X29", "LR"], 504, "offset")],
  [[0xbf], "save_fplr_x", saved(["X29", "LR"], -512, "preIndex")],
  [[0xc7, 0xff], "alloc_m", { kind: "allocate", amount: 32752, unit: "bytes" }],
  [[0xc9, 0x3f], "save_regp", saved(["X23", "X24"], 504, "offset")],
  [[0xce, 0xbf], "save_regp_x", saved(["X29", "LR"], -512, "preIndex")],
  [[0xd0, 0], "save_reg", saved(["X19"], 0, "offset")],
  [[0xd2, 0xff], "save_reg", saved(["LR"], 504, "offset")],
  [[0xd5, 0x5f], "save_reg_x", saved(["X29"], -256, "preIndex")],
  [[0xd7, 0x7f], "save_lrpair", saved(["X29", "LR"], 504, "offset")],
  [[0xd6, 0], "save_lrpair", saved(["X19", "LR"], 0, "offset")],
  [[0xd9, 0x3f], "save_fregp", saved(["D12", "D13"], 504, "offset")],
  [[0xdb, 0x3f], "save_fregp_x", saved(["D12", "D13"], -512, "preIndex")],
  [[0xda, 0], "save_fregp_x", saved(["D8", "D9"], -8, "preIndex")],
  [[0xdc, 0], "save_freg", saved(["D8"], 0, "offset")],
  [[0xdd, 0xff], "save_freg", saved(["D15"], 504, "offset")],
  [[0xde, 0xff], "save_freg_x", saved(["D15"], -256, "preIndex")],
  [[0xdf, 0xff], "alloc_z", { kind: "allocate", amount: 255, unit: "vectorLengths" }],
  [[0xe0, 0xff, 0xff, 0xff], "alloc_l", { kind: "allocate", amount: 268435440, unit: "bytes" }],
  [[0xe0, 1, 2, 3], "alloc_l", { kind: "allocate", amount: 1056816, unit: "bytes" }],
  [[0xe1], "set_fp", { kind: "frame", displacement: 0 }],
  [[0xe2, 0xff], "add_fp", { kind: "frame", displacement: 2040 }],
  [[0xe7, 0x1e, 0x3f], "save_any_reg", saved(["LR"], 504, "offset")],
  [[0xe7, 0x40, 0], "save_any_reg", saved(["X0", "X1"], 0, "offset")],
  [[0xe7, 0x5d, 1], "save_any_reg", saved(["X29", "LR"], 16, "offset")],
  [[0xe7, 0x7d, 0x3f], "save_any_reg", saved(["X29", "LR"], -1024, "preIndex")],
  [[0xe7, 0x1f, 0x7f], "save_any_reg", saved(["D31"], 504, "offset")],
  [[0xe7, 0x20, 0x40], "save_any_reg", saved(["D0"], -16, "preIndex")],
  [[0xe7, 0x5e, 0x7f], "save_any_reg", saved(["D30", "D31"], 1008, "offset")],
  [[0xe7, 0x1f, 0xbf], "save_any_reg", saved(["Q31"], 1008, "offset")],
  [[0xe7, 0x60, 0x80], "save_any_reg", saved(["Q0", "Q1"], -16, "preIndex")],
  [[0xe7, 0x6f, 0xff], "save_zreg", { kind: "save", registers: ["Z23"], displacement: 255,
    addressing: "offset", unit: "vectorLengths" }],
  [[0xe7, 0x7f, 0xff], "save_preg", { kind: "save", registers: ["P15"], displacement: 255,
    addressing: "offset", unit: "predicateLengths" }],
  [[0xe7, 0x70, 0xff], "save_vg_sm", saved(["VG", "SM"], 2040, "offset")]
];

for (const [bytes, opcode, body] of vectors) {
  void test(`ARM64 ${opcode} operand vector ${bytes.join(",")}`, () => {
    const buffer = Uint8Array.from([255, 255, ...bytes, 255, 255]);
    const issues: string[] = [];
    const operation = decodeArm64UnwindOperation(new DataView(buffer.buffer, 2, bytes.length), 0, issues);

    assert.deepEqual(operation, { opcode, offset: 0, byteLength: bytes.length, ...body });
    assert.deepEqual(issues, []);
  });
}

for (const [byte, opcode] of [[0xe3, "nop"], [0xe4, "end"], [0xe5, "end_c"], [0xe6, "save_next"],
  [0xe8, "trap_frame"], [0xe9, "machine_frame"], [0xea, "context"], [0xeb, "ec_context"],
  [0xec, "clear_unwound_to_call"], [0xfc, "pac_sign_lr"]] as const) {
  void test(`ARM64 marker ${opcode}`, () => {
    const issues: string[] = [];
    assert.deepEqual(decodeArm64UnwindOperation(new DataView(Uint8Array.of(0, byte).buffer), 1, issues),
      { opcode, offset: 1, byteLength: 1, kind: "marker" });
    assert.deepEqual(issues, []);
  });
}

for (const offset of [-1, 0.5, NaN, Infinity, 1]) {
  void test(`ARM64 rejects operation offset ${offset}`, () => {
    const issues: string[] = [];
    assert.equal(decodeArm64UnwindOperation(new DataView(Uint8Array.of(0xe4).buffer), offset, issues), null);
    assert.match(issues[0]!, /offset is out of bounds/);
  });
}

for (const bytes of [[0xe7, 0x80], [0xe7, 0x5e, 0], [0xe7, 0x1f, 0], [0xe7, 0x5f, 0x40],
  [0xe7, 0x5f, 0x80], [0xe7, 0x11, 0xc0], [0xe7, 0x12, 0xc0], [0xe7, 0x13, 0xc0],
  [0xcb, 0xff], [0xd3, 0xff], [0xd7, 0xff]]) {
  void test(`ARM64 diagnoses reserved operand vector ${bytes.join(",")}`, () => {
    const issues: string[] = [];
    assert.equal(decodeArm64UnwindOperation(new DataView(Uint8Array.from(bytes).buffer), 0, issues), null);
    assert.match(issues.join(" "), /reserved|register bank/);
  });
}

for (const bytes of [[0xc0], [0xe0, 1, 2], [0xe2], [0xe7], [0xe7, 0]]) {
  void test(`ARM64 bounds operands by the view for ${bytes.join(",")}`, () => {
    const buffer = Uint8Array.from([...bytes, 0, 0, 0, 0]);
    const issues: string[] = [];
    assert.equal(decodeArm64UnwindOperation(new DataView(buffer.buffer, 0, bytes.length), 0, issues), null);
    assert.match(issues[0]!, /truncated operands/);
  });
}

for (const byte of [0xed, 0xee, 0xef, 0xf0, 0xf8, 0xf9, 0xfa, 0xfb, 0xfd, 0xfe, 0xff]) {
  void test(`ARM64 retains unknown opcode ${byte} in its diagnostic`, () => {
    const issues: string[] = [];
    assert.equal(decodeArm64UnwindOperation(new DataView(Uint8Array.of(byte).buffer), 0, issues), null);
    assert.equal(issues[0], `ARM64 unwind opcode ${byte} at byte 0 is unknown or reserved.`);
  });
}
