import assert from "node:assert/strict";
import { test } from "node:test";
import { renderOmap } from "../../../../renderers/pe/omap.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";

void test("OMAP summarizes both mapping directions without address tables", () => {
  const out: string[] = [];
  const records = [{ rva: 100, rvaTo: 100 }, { rva: 120, rvaTo: 0 }, { rva: 130, rvaTo: 200 }];
  renderOmap({ ...createDebugViewEntry(7, 0, 0), omap: { records } }, 0, out);
  renderOmap({ ...createDebugViewEntry(8, 0, 0), omap: { records } }, 1, out);

  assert.match(out.join(""), /Optimized image to original source layout/);
  assert.match(out.join(""), /Original source layout to optimized image/);
  assert.match(out.join(""), /Unmapped regions<\/dt><dd>1/);
  assert.match(out.join(""), /Unchanged region starts<\/dt><dd>1/);
  assert.match(out.join(""), /Moved region starts<\/dt><dd>1/);
  assert.match(out.join(""), /20 bytes/);
  assert.doesNotMatch(out.join(""), /<table|0x/);
});

void test("OMAP refuses to infer byte coverage from unordered or duplicate inputs", () => {
  const out: string[] = [];
  renderOmap({ ...createDebugViewEntry(7, 0, 0), omap: { records: [
    { rva: 200, rvaTo: 300 }, { rva: 200, rvaTo: 400 }
  ] } }, 0, out);

  assert.match(out.join(""), /Ambiguous; not strictly increasing/);
  assert.match(out.join(""), /Unavailable/);
});

void test("OMAP handles absent, empty and final unbounded mapping records", () => {
  const out: string[] = [];
  renderOmap(createDebugViewEntry(7, 0, 0), 0, out);
  assert.deepEqual(out, []);
  renderOmap({ ...createDebugViewEntry(7, 0, 0), omap: { records: [] } }, 0, out);
  assert.match(out.join(""), /No complete OMAP records/);
  assert.match(out.join(""), /final region's length is not stored/);
});