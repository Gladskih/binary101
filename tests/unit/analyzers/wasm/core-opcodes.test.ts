import assert from "node:assert/strict";
import { test } from "node:test";
import { CORE_OPCODES } from "../../../../analyzers/wasm/core-opcodes.js";
import { upstreamWasmOpcodes } from "../../../fixtures/wasm-opcode-oracle.js";

void test("core opcode names and encodings match the pinned upstream source", () => {
  assert.deepEqual(CORE_OPCODES, upstreamWasmOpcodes(0));
});
