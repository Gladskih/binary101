"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import {
  createGoRuntimeFunctionTableModel,
  renderGoRuntime
} from "../../../../renderers/pe/go-runtime.js";
import type { GoRuntimeFunction } from "../../../../analyzers/go-runtime/types.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";

const createFunctions = (count: number): GoRuntimeFunction[] =>
  Array.from({ length: count }, (_, index) => ({
    name: `main.function${index}`,
    start: 0x1000n + BigInt(index * 0x10),
    end: 0x1010n + BigInt(index * 0x10)
  }));

void test("renderGoRuntime renders confirmed locations, counts, text, and functions", () => {
  const pe = createBasePe();
  pe.opt.ImageBase = 0x1400_0000_0n;
  pe.rvaToOff = rva => rva === 0x2000 ? 0x400 : rva === 0x3000 ? 0x800 : null;
  pe.goRuntime = {
    layout: "go1.20+",
    pointerSize: 8,
    pcHeaderAddress: 0x1400_0200_0n,
    moduleDataAddress: 0x1400_0300_0n,
    fileCount: 3,
    textRange: { start: 0x1400_0100_0n, end: 0x1400_0104_0n },
    functions: [
      { name: "runtime.main", start: 0x1400_0100_0n, end: 0x1400_0102_0n },
      { name: "main.<unsafe>", start: 0x1400_0102_0n, end: 0x1400_0104_0n }
    ]
  };
  const out: string[] = [];

  renderGoRuntime(pe, out);

  const html = out.join("");
  assert.match(html, /Go runtime metadata/);
  assert.match(html, /go1\.20\+/);
  assert.match(html, /RVA 0x2000, file 0x400/);
  assert.match(html, /RVA 0x3000, file 0x800/);
  assert.match(html, /runtime\.main/);
  assert.match(html, /main\.&lt;unsafe>/);
  assert.doesNotMatch(html, /main\.<unsafe>/);
});

void test("renderGoRuntime emits nothing without strict metadata confirmation", () => {
  const out: string[] = [];

  renderGoRuntime(createBasePe(), out);

  assert.deepEqual(out, []);
});

void test("createGoRuntimeFunctionTableModel exposes stable sortable boundaries", () => {
  const model = createGoRuntimeFunctionTableModel([
    { name: "main.main", start: 0x1010n, end: 0x1040n }
  ]);

  assert.equal(model.rowCount, 1);
  assert.deepEqual(model.rowAt(0)?.cells.map(cell => cell.html), [
    "1",
    "main.main",
    "0x1010",
    "0x1040",
    "0x30"
  ]);
  assert.equal(model.sortValueAt(0, 2), "4112");
  assert.equal(model.sortValueAt(0, 0), "1");
  assert.equal(model.sortValueAt(0, 1), "main.main");
  assert.equal(model.sortValueAt(0, 3), "4160");
  assert.equal(model.sortValueAt(0, 4), "48");
  assert.equal(model.sortValueAt(2, 0), "");
  assert.equal(model.rowAt(2), null);
});

void test("renderGoRuntime pages large function tables", () => {
  const pe = createBasePe();
  pe.goRuntime = {
    layout: "go1.20+",
    pointerSize: 8,
    pcHeaderAddress: 0x402000n,
    moduleDataAddress: 0x403000n,
    fileCount: 1,
    textRange: { start: 0x401000n, end: 0x402000n },
    functions: createFunctions(251)
  };
  pe.rvaToOff = () => null;
  const out: string[] = [];

  renderGoRuntime(pe, out);

  const html = out.join("");
  assert.match(html, /data-paged-sortable-table-id="pe-go-runtime-functions"/);
  assert.doesNotMatch(html, /, file 0x/);
  assert.equal(getPePagedTableModel(pe, "pe-go-runtime-functions")?.rowCount, 251);
  assert.equal(getPePagedTableModel(pe, "unknown-go-table"), null);
});
