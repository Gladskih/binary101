import assert from "node:assert/strict";
import { test } from "node:test";
import { renderFpoStatistics, renderPogoStatistics } from "../../../../renderers/pe/debug-statistics.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";

void test("FPO summarizes every frame without truncation or address rows", () => {
  const out: string[] = [];
  renderFpoStatistics({ ...createDebugViewEntry(3, 0, 0), fpo: { records: Array.from(
    { length: 26 }, () => ({ startOffset: 0x1234, procedureSize: 32, localDwordCount: 2,
      parameterDwordCount: 1, prologByteCount: 3, savedRegisterCount: 2,
      usesBasePointer: true, hasStructuredExceptionHandling: true, frameType: 0 })) } }, out);

  assert.match(out.join(""), /Frames with SEH/);
  assert.match(out.join(""), /26/);
  assert.doesNotMatch(out.join(""), /0x00001234|<th>Start/);
});

void test("POGO aggregates layout without dumping address lists", () => {
  const out: string[] = [];
  renderPogoStatistics({ ...createDebugViewEntry(13, 0, 0), pogo: {
    signature: 0, signatureName: "ZERO", entries: [{ startRva: 0x1234, size: 32, name: ".text$mn" }]
  } }, out);

  assert.match(out.join(""), /Largest region/);
  assert.match(out.join(""), /\.text\$mn/);
  assert.doesNotMatch(out.join(""), /0x00001234|<th>Start RVA/);
});

void test("debug statistics omit absent payloads and handle empty collections", () => {
  const out: string[] = [];
  renderFpoStatistics(createDebugViewEntry(3, 0, 0), out);
  renderPogoStatistics(createDebugViewEntry(13, 0, 0), out);
  assert.deepEqual(out, []);
  renderFpoStatistics({ ...createDebugViewEntry(3, 0, 0), fpo: { records: [] } }, out);
  renderPogoStatistics({ ...createDebugViewEntry(13, 0, 0), pogo: {
    signature: 0, signatureName: "ZERO", entries: []
  } }, out);
  assert.match(out.join(""), /Record count<\/dt><dd>0/);
  assert.doesNotMatch(out.join(""), /Largest region/);
});

void test("FPO statistics distinguish frame kinds, protections and DWORD stack sizes", () => {
  const out: string[] = [];
  const frame = { startOffset: 4096, procedureSize: 32, localDwordCount: 2,
    parameterDwordCount: 3, prologByteCount: 18, savedRegisterCount: 5,
    hasStructuredExceptionHandling: true, usesBasePointer: true, frameType: 2 };
  renderFpoStatistics({ ...createDebugViewEntry(3, 0, 0), fpo: { records: [frame,
    { ...frame, procedureSize: 64, localDwordCount: 4, parameterDwordCount: 1,
      hasStructuredExceptionHandling: false, usesBasePointer: false, frameType: 0 }
  ] } }, out);
  const html = out.join("");

  assert.match(html, /Sum of procedure sizes<\/dt><dd>96 B \(96 bytes\)/);
  assert.match(html, /Frames with SEH<\/dt><dd>1/);
  assert.match(html, /Frames using a base pointer<\/dt><dd>1/);
  assert.match(html, /Largest local stack allocation<\/dt><dd>16 B \(16 bytes\)/);
  assert.match(html, /Largest parameter area<\/dt><dd>12 B \(12 bytes\)/);
  assert.match(html, /<td>FPO<\/td><td class="peNumeric">1/);
  assert.match(html, /<td>Trap<\/td><td class="peNumeric">0/);
  assert.match(html, /<td>Task state segment<\/td><td class="peNumeric">1/);
  assert.match(html, /<td>Standard frame<\/td><td class="peNumeric">0/);
});

void test("POGO statistics count duplicate names, empty regions and declared sizes", () => {
  const out: string[] = [];
  renderPogoStatistics({ ...createDebugViewEntry(13, 0, 0), pogo: {
    signature: 0, signatureName: "ZERO", entries: [
      { startRva: 0, size: 0, name: "<first>" },
      { startRva: 0, size: 64, name: "region" },
      { startRva: 0, size: 16, name: "region" },
      { startRva: 0, size: 8, name: "" }
    ]
  } }, out);
  const html = out.join("");

  assert.match(html, /Entry count<\/dt><dd>4/);
  assert.match(html, /Sum of region sizes<\/dt><dd>88 B \(88 bytes\)/);
  assert.match(html, /Distinct region names<\/dt><dd>3/);
  assert.match(html, /Empty regions<\/dt><dd>1/);
  assert.match(html, /Largest region<\/dt><dd>region \(64 B \(64 bytes\)\)/);
  assert.doesNotMatch(html, /<first>/);
});
