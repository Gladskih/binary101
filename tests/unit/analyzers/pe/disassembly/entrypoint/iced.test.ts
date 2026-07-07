import assert from "node:assert/strict";
import { test } from "node:test";
import { isIcedModule } from "../../../../../../analyzers/pe/disassembly/entrypoint/iced.js";
import { fakeIced } from "../../../../../helpers/pe-entrypoint-disassembly-fixture.js";

void test("isIcedModule accepts the entrypoint iced fixture", () => {
  assert.equal(isIcedModule(fakeIced), true);
});

void test("isIcedModule rejects modules without MemorySize", () => {
  const withoutMemorySize: Record<string, unknown> = { ...fakeIced };
  delete withoutMemorySize["MemorySize"];
  assert.equal(isIcedModule(withoutMemorySize), false);
});
