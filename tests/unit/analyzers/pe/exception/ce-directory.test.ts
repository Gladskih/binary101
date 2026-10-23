import assert from "node:assert/strict";
import { test } from "node:test";
import { isCeExceptionMachine, parseCeExceptionDirectory } from "../../../../../analyzers/pe/exception/ce-directory.js";
import { parsePeHeaders, isPeWindowsCore } from "../../../../../analyzers/pe/core/index.js";
import { parseExceptionDirectory } from "../../../../../analyzers/pe/exception/index.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { createCeExceptionPe, ceFunctionWord } from "../../../../fixtures/pe-ce-exception.js";

for (const machine of [0x1c0, 0x1c2, 0x1a2, 0x1a3, 0x1a6, 0x1f0, 0x1f1]) {
  void test(`CE machine ${machine.toString(16)} decodes image tables and raw-only debug copies`, async () => {
    const file = createCeExceptionPe(machine, ceFunctionWord(4, 1, 4, 1));
    const core = await parsePeHeaders(file);
    assert.ok(core && isPeWindowsCore(core));
    const expected = await parseCeExceptionDirectory(file, core.dataDirs, core.rvaToOff, machine, core.opt);
    const parsed = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, machine,
      undefined, undefined, core.opt);
    const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, machine, core.opt);

    assert.equal(expected?.format, "ce");
    assert.deepEqual(expected?.beginRvas, [0x1080]);
    assert.deepEqual(expected?.rangeLengths, [16]);
    assert.deepEqual(expected?.handlerRvas, [0x1100]);
    assert.deepEqual(expected?.issues, []);
    assert.deepEqual(parsed, expected);
    assert.deepEqual(debug.entries[0]?.exception, expected);
    assert.equal(debug.warning, null);
  });
}

void test("CE machine selection keeps PowerPC subsystem context and distinct ARMNT semantics", async () => {
  const core = await parsePeHeaders(createCeExceptionPe());
  assert.ok(core && isPeWindowsCore(core));

  assert.equal(isCeExceptionMachine(0x1f0), false);
  assert.equal(isCeExceptionMachine(0x1f0, { ...core.opt, Subsystem: 2 }), false);
  assert.equal(isCeExceptionMachine(0x1f0, core.opt), true);
  assert.equal(isCeExceptionMachine(0x1c2, { ...core.opt, Subsystem: 2 }), true);
  assert.equal(isCeExceptionMachine(0x1c4, core.opt), false);
  assert.equal(isCeExceptionMachine(0x1a8, core.opt), false);
  assert.equal(await parseCeExceptionDirectory(createCeExceptionPe(), [], core.rvaToOff, 0x1c0, core.opt), null);
});

for (const [rva, size, offset, issue] of [[0, 8, 0, /RVA is 0/], [0x2000, 8, null, /could not be mapped/],
  [0x2000, 8, -1, /outside/], [0x2000, 8, 0.5, /outside/], [0x2000, 8, 10000, /outside/],
  [0x2000, 0, 0, /smaller than one entry/]] as const) {
  void test(`CE directory validates coordinates ${rva}/${size}/${offset}`, async () => {
    const file = createCeExceptionPe();
    const core = await parsePeHeaders(file);
    assert.ok(core && isPeWindowsCore(core));
    const parsed = await parseCeExceptionDirectory(file, [{ name: "EXCEPTION", rva, size }],
      () => offset, 0x1c0, core.opt);

    assert.match(parsed!.issues[0]!, issue);
  });
}

void test("CE directory accepts offset zero while rejecting an offset exactly at EOF", async () => {
  const file = createCeExceptionPe();
  const core = await parsePeHeaders(file);
  assert.ok(core && isPeWindowsCore(core));
  const first = await parseCeExceptionDirectory(file, [{ name: "EXCEPTION", rva: 0x2000, size: 8 }],
    rva => rva - 0x2000, 0x1c0, core.opt);
  const eof = await parseCeExceptionDirectory(file, core.dataDirs, () => file.size, 0x1c0, core.opt);
  const absent = await parseCeExceptionDirectory(file, [{ name: "EXCEPTION", rva: 0, size: 0 }],
    core.rvaToOff, 0x1c0, core.opt);
  const missingBase = await parseCeExceptionDirectory(file, core.dataDirs, core.rvaToOff, 0x1c0);

  assert.equal(first?.functionCount, 1);
  assert.match(eof!.issues[0]!, /outside/);
  assert.equal(absent, null);
  assert.match(missingBase!.issues[0]!, /ImageBase/);
});

void test("full CE PE parsing forwards image-base context to both table locations", async () => {
  const parsed = await parsePe(createCeExceptionPe());

  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.equal(parsed.exception?.format, "ce");
  assert.deepEqual(parsed.exception?.beginRvas, [0x1080]);
  assert.deepEqual(parsed.debug?.entries?.[0]?.exception, parsed.exception);
});
