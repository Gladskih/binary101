import assert from "node:assert/strict";
import { test } from "node:test";
import { createElfHashTableModel, renderElfHashTables } from "../../../../renderers/elf/hash-tables.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";

void test("renders all hash arrays with page model and escaped warnings", () => {
  const elf = relocationFixture().elf;
  elf.hashTables = [{ kind: "gnu", offset: 64, buckets: [1], chains: [3], bloom: [4n],
    bloomShift: 5, symbolOffset: 1, issues: ["<invalid>"] }];
  const model = createElfHashTableModel(elf.hashTables[0]!);
  assert.equal(model.rowCount, 3);
  assert.equal(model.sortValueAt(0, 0), "Bucket");
  assert.equal(model.sortValueAt(1, 2), "0x3 (end)");
  assert.equal(model.sortValueAt(2, 2), "0x4");
  assert.equal(model.rowAt(3), null);
  assert.equal(model.sortValueAt(3, 0), "");
  const out: string[] = [];
  renderElfHashTables(elf, out);
  assert.match(out.join(""), /Bloom/);
  assert.match(out.join(""), /&lt;invalid>/);
});
