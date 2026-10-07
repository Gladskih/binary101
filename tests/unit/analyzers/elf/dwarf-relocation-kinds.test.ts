import assert from "node:assert/strict";
import { test } from "node:test";
import { elfDwarfRelocationKind } from "../../../../analyzers/elf/dwarf-relocation-kinds.js";

void test("DWARF data relocation descriptions use architecture-specific widths and overflow rules", () => {
  assert.deepEqual(elfDwarfRelocationKind(62, 1), { width: 8, operation: "absolute", overflow: "truncate" });
  assert.deepEqual(elfDwarfRelocationKind(62, 2), { width: 4, operation: "relative", overflow: "signed" });
  assert.deepEqual(elfDwarfRelocationKind(3, 1), { width: 4, operation: "absolute", overflow: "truncate" });
  assert.deepEqual(elfDwarfRelocationKind(183, 259), { width: 2, operation: "absolute", overflow: "mixed" });
  assert.deepEqual(elfDwarfRelocationKind(243, 35), { width: 4, operation: "add", overflow: "truncate" });
  assert.deepEqual(elfDwarfRelocationKind(243, 39), { width: 4, operation: "subtract", overflow: "truncate" });
  assert.equal(elfDwarfRelocationKind(62, 999), null);
  assert.equal(elfDwarfRelocationKind(999, 1), null);
});
