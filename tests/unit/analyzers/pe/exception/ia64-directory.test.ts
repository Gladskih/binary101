import assert from "node:assert/strict";
import { test } from "node:test";
import { parseIa64ExceptionDirectory } from "../../../../../analyzers/pe/exception/ia64-directory.js";
import { parsePeHeaders, isPeWindowsCore } from "../../../../../analyzers/pe/core/index.js";
import { parseExceptionDirectory } from "../../../../../analyzers/pe/exception/index.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { createIa64ExceptionPe } from "../../../../fixtures/pe-ia64-exception.js";
import { parseExceptionDebugInfo } from "../../../../../analyzers/pe/debug/exception.js";

void test("IA64 dispatches image tables and raw-only debug copies using RVA fields in PE32+", async () => {
  const file = createIa64ExceptionPe();
  const core = await parsePeHeaders(file);
  assert.ok(core && isPeWindowsCore(core));
  const expected = await parseIa64ExceptionDirectory(file, core.dataDirs, core.rvaToOff);
  const parsed = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine, core.opt);

  assert.equal(expected?.format, "ia64");
  assert.deepEqual(expected?.beginRvas, [0x1000, 0x1040]);
  assert.deepEqual(expected?.rangeLengths, [64, 64]);
  assert.equal(expected?.uniqueUnwindInfoCount, 1);
  assert.deepEqual(parsed, expected);
  assert.deepEqual(debug.entries[0]?.exception, expected);
  assert.equal(debug.warning, null);
});

for (const [rva, size, offset, issue] of [[0, 12, 0, /RVA is 0/], [0x1100, 12, null, /could not be mapped/],
  [0x1100, 12, -1, /outside/], [0x1100, 12, 0.5, /outside/], [0x1100, 12, 10000, /outside/],
  [0x1100, 0, 0, /smaller than one entry/]] as const) {
  void test(`IA64 directory validates coordinates ${rva}/${size}/${offset}`, async () => {
    const file = createIa64ExceptionPe();
    const parsed = await parseIa64ExceptionDirectory(file, [{ name: "EXCEPTION", rva, size }], () => offset);

    assert.equal(parsed?.format, "ia64");
    assert.match(parsed!.issues[0]!, issue);
  });
}

void test("IA64 directory distinguishes absence, offset zero and an offset exactly at EOF", async () => {
  const file = createIa64ExceptionPe();
  const first = await parseIa64ExceptionDirectory(file, [{ name: "EXCEPTION", rva: 0x1100, size: 12 }],
    rva => rva - 0x1100);
  const eof = await parseIa64ExceptionDirectory(file, [{ name: "EXCEPTION", rva: 0x1100, size: 12 }], () => file.size);

  assert.equal(first?.functionCount, 1);
  assert.match(eof!.issues[0]!, /outside/);
  assert.equal(await parseIa64ExceptionDirectory(file, [], () => 0), null);
  assert.equal(await parseIa64ExceptionDirectory(file, [{ name: "EXCEPTION", rva: 0, size: 0 }], () => 0), null);
});

void test("full IA64 PE parsing retains both exception-table locations", async () => {
  const parsed = await parsePe(createIa64ExceptionPe());

  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.equal(parsed.exception?.format, "ia64");
  assert.deepEqual(parsed.debug?.entries?.[0]?.exception, parsed.exception);
});

void test("IA64 decodes a standalone raw copy without an origin RVA or image directory", async () => {
  const file = createIa64ExceptionPe();
  const core = await parsePeHeaders(file);
  assert.ok(core && isPeWindowsCore(core));
  const warnings: string[] = [];
  const parsed = await parseExceptionDebugInfo(file, core.rvaToOff, 0, file.size - 24, 24,
    0x200, warning => warnings.push(warning));

  assert.equal(parsed?.format, "ia64");
  assert.deepEqual(parsed.beginRvas, [0x1000, 0x1040]);
  assert.deepEqual(parsed.rangeLengths, [64, 64]);
  assert.deepEqual(warnings, []);
});
