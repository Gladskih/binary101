import assert from "node:assert/strict";
import { test } from "node:test";
import { SIMD_OPCODES } from "../../../../analyzers/wasm/simd-opcodes.js";
import { upstreamWasmOpcodes } from "../../../fixtures/wasm-opcode-oracle.js";

void test("SIMD opcode names and encodings match the pinned upstream source", () => {
  // SIMD and relaxed SIMD use the 0xfd prefix.
  assert.deepEqual(SIMD_OPCODES, upstreamWasmOpcodes(0xfd));
});
