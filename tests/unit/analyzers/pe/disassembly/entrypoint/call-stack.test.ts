"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createCallStackState,
  createReturnStackState
} from "../../../../../../analyzers/pe/disassembly/entrypoint/call-stack.js";
import { createEmulationState } from "../../../../../../analyzers/pe/disassembly/entrypoint/emulation/index.js";
import type { IcedModule } from "../../../../../../analyzers/pe/disassembly/entrypoint/iced.js";
import {
  fakeIced
} from "../../../../../helpers/pe-entrypoint-disassembly-fixture.js";

const iced = fakeIced as unknown as IcedModule;

void test("createReturnStackState consumes the modeled return-address slot", () => {
  const called = createCallStackState(iced, createEmulationState(64), 0x140001005n);
  const returned = createReturnStackState(iced, called);

  assert.deepEqual(returned.registers.get("RSP"), {
    kind: "known",
    value: 0x100000000000n,
    bits: 64
  });
  assert.equal(returned.memory.size, 0);
});
