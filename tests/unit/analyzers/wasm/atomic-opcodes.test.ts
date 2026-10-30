import assert from "node:assert/strict";
import { test } from "node:test";
import { ATOMIC_OPCODES } from "../../../../analyzers/wasm/atomic-opcodes.js";
import { upstreamWasmOpcodes } from "../../../fixtures/wasm-opcode-oracle.js";

void test("atomic opcode names and encodings match the pinned upstream source", () => {
  // Threads instructions use the 0xfe prefix.
  assert.deepEqual(ATOMIC_OPCODES, upstreamWasmOpcodes(0xfe));
});
