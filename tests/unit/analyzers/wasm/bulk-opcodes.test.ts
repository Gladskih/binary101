import assert from "node:assert/strict";
import { test } from "node:test";
import { BULK_OPCODES } from "../../../../analyzers/wasm/bulk-opcodes.js";
import { upstreamWasmOpcodes } from "../../../fixtures/wasm-opcode-oracle.js";

void test("bulk opcode names and encodings match the pinned upstream source", () => {
  // Miscellaneous opcode prefix: core binary instructions, prefix 0xfc.
  assert.deepEqual(BULK_OPCODES, upstreamWasmOpcodes(0xfc));
});
