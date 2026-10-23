import assert from "node:assert/strict";
import { test } from "node:test";
import { getNtRiscExceptionFormat, parseNtRiscExceptionDirectory } from "../../../../../analyzers/pe/exception/nt-risc-directory.js";
import { parsePeHeaders, isPeWindowsCore } from "../../../../../analyzers/pe/core/index.js";
import { parseExceptionDirectory } from "../../../../../analyzers/pe/exception/index.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";
import { createNtRiscPe, createNtRiscSecondaryPe, createAlphaRiscPe } from "../../../../fixtures/pe-risc-exception.js";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";

for (const machine of [0x162, 0x166, 0x168, 0x184, 0x1f0, 0x1f1, 0x284]) {
  void test(`NT RISC machine ${machine.toString(16)} uses image VAs in directories and debug copies`, async () => {
    const file = createNtRiscPe(machine);
    const core = await parsePeHeaders(file);
    assert.ok(core && isPeWindowsCore(core));
    const expected = await parseNtRiscExceptionDirectory(file, core.dataDirs, core.rvaToOff, machine, core.opt);
    const directory = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, machine,
      undefined, undefined, core.opt);
    const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, machine, core.opt);

    assert.equal(expected?.functionCount, 1);
    assert.deepEqual(expected?.beginRvas, [0x1000]);
    assert.deepEqual(expected?.rangeLengths, [64]);
    assert.deepEqual(expected?.issues, []);
    assert.deepEqual(directory, expected);
    assert.deepEqual(debug.entries[0]?.exception, expected);
    assert.equal(debug.warning, null);
  });
}

void test("Alpha mode and secondary-reference summaries agree between the directory and debug copy", async () => {
  const file = createAlphaRiscPe();
  const core = await parsePeHeaders(file);
  assert.ok(core && isPeWindowsCore(core));
  const directory = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, 0x184,
    undefined, undefined, core.opt);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, 0x184, core.opt);
  assert.deepEqual(debug.entries[0]?.exception, directory);
  assert.deepEqual(directory?.alphaPrologs, { resolvedSecondaryRanges: 1, unresolvedSecondaryRanges: 0 });
  assert.deepEqual(directory?.riscExceptionModes, [1, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(directory?.issues, []);
});

void test("NT RISC selection does not guess the PowerPC ABI without a subsystem", async () => {
  const core = await parsePeHeaders(createNtRiscPe(0x1f0));
  assert.ok(core && isPeWindowsCore(core));

  assert.equal(getNtRiscExceptionFormat(0x1f0), undefined);
  assert.equal(getNtRiscExceptionFormat(0x1f0, { ...core.opt, Subsystem: 9 }), undefined);
  assert.equal(getNtRiscExceptionFormat(0x1f0, core.opt), "nt-risc32");
  assert.equal(getNtRiscExceptionFormat(0x8664, core.opt), undefined);
  assert.equal(await parseNtRiscExceptionDirectory(createNtRiscPe(), [], core.rvaToOff, 0x166, core.opt), null);
});

for (const [rva, size, offset, issue] of [
  [0, 20, 0, /RVA is 0/], [0x1100, 20, null, /could not be mapped/],
  [0x1100, 20, -1, /outside/], [0x1100, 20, 0.5, /outside/], [0x1100, 20, 0x10000, /outside/]
] as const) {
  void test(`NT RISC directory validates mapping ${rva}/${size}/${offset}`, async () => {
    const file = createNtRiscPe();
    const core = await parsePeHeaders(file);
    assert.ok(core && isPeWindowsCore(core));
    const parsed = await parseNtRiscExceptionDirectory(file, [{ name: "EXCEPTION", rva, size }],
      () => offset, 0x166, core.opt);

    assert.match(parsed!.issues.join(" | "), issue);
  });
}

void test("full PE analysis forwards the actual header to both NT RISC paths", async () => {
  const parsed = await parsePe(createNtRiscPe());

  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.deepEqual(parsed.exception?.beginRvas, [0x1000]);
  assert.deepEqual(parsed.debug?.entries?.[0]?.exception?.beginRvas, [0x1000]);
});

void test("NT RISC directory keeps absent tables distinct from missing ImageBase context", async () => {
  const file = createNtRiscPe();
  const core = await parsePeHeaders(file);
  assert.ok(core && isPeWindowsCore(core));
  const empty = await parseNtRiscExceptionDirectory(file, [{ name: "EXCEPTION", rva: 0, size: 0 }],
    core.rvaToOff, 0x166, core.opt);
  const missing = await parseNtRiscExceptionDirectory(file, core.dataDirs, core.rvaToOff, 0x166);

  assert.equal(empty, null);
  assert.equal(missing?.functionCount, 0);
  assert.match(missing!.issues[0]!, /ImageBase/);
});

void test("NT RISC directory accepts offset zero and rejects an offset exactly at EOF", async () => {
  const file = createNtRiscPe();
  const core = await parsePeHeaders(file);
  assert.ok(core && isPeWindowsCore(core));
  const atStart = await parseNtRiscExceptionDirectory(file, [{ name: "EXCEPTION", rva: 0x1100, size: 20 }],
    rva => rva - 0x1100, 0x166, core.opt);
  const atEnd = await parseNtRiscExceptionDirectory(file, core.dataDirs, () => file.size, 0x166, core.opt);
  const noSize = await parseNtRiscExceptionDirectory(file, [{ name: "EXCEPTION", rva: 0x1100, size: 0 }],
    core.rvaToOff, 0x166, core.opt);

  assert.equal(atStart?.functionCount, 1);
  assert.match(atEnd!.issues[0]!, /outside/);
  assert.match(noSize!.issues[0]!, /smaller than one entry/);
});

void test("NT RISC debug and image tables retain secondary ranges without guessing their handler data", async () => {
  const file = createNtRiscSecondaryPe();
  const core = await parsePeHeaders(file);
  assert.ok(core && isPeWindowsCore(core));
  const parsed = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine,
    undefined, undefined, core.opt);
  const copy = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine, core.opt);

  assert.deepEqual(parsed?.beginRvas, [0x1000, 0x1040]);
  assert.equal(parsed?.riscPrologs?.count, 1);
  assert.equal(parsed?.handlerUnwindInfoCount, 0);
  assert.deepEqual(parsed?.handlerRvas, []);
  assert.deepEqual(parsed?.issues,
    ["NT RISC prolog location is outside its function; indirect prolog metadata is not decoded."]);
  assert.deepEqual(copy.entries[0]?.exception, parsed);
});
