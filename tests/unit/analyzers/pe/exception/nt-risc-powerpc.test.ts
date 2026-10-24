import assert from "node:assert/strict";
import { test } from "node:test";
import { parseNtRiscExceptionTable } from "../../../../../analyzers/pe/exception/nt-risc.js";
import { riscExceptionRows, riscExceptionImage, riscExceptionMap,
  createPowerPcCodeSignificancePe } from "../../../../fixtures/pe-risc-exception.js";
import { parsePeHeaders, isPeWindowsCore } from "../../../../../analyzers/pe/core/index.js";
import { parseExceptionDirectory } from "../../../../../analyzers/pe/exception/index.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";

void test("PowerPC code-significance counts agree in PE directories and embedded debug copies", async () => {
  const file = createPowerPcCodeSignificancePe();
  const core = await parsePeHeaders(file);
  assert.ok(core && isPeWindowsCore(core));
  const parsed = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine,
    undefined, undefined, core.opt);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine, core.opt);

  assert.deepEqual(parsed?.powerPcCodeSignificance, [1, 1, 1]);
  assert.deepEqual(parsed?.issues, []);
  assert.deepEqual(debug.entries[0]?.exception, parsed);
  assert.equal(debug.warning, null);
});

// GNU binutils 2.34 peXXigen.c recognizes HandlerData 1-3 when the handler is null.
// dlltool.c emits 3 for PowerPC glue, with a tagged prolog end at begin + 13.
// https://gnu.googlesource.com/binutils-gdb/+/refs/tags/binutils-2_34/binutils/dlltool.c#2855
for (const machine of [0x1f0, 0x1f1]) {
  void test(`PowerPC ${machine} distinguishes handler-less code markers from data VAs`, async () => {
    const source = riscExceptionRows([
      [0x401000n, 0x401018n, 0n, 1n, 0x40100dn],
      [0x401020n, 0x401038n, 0n, 2n, 0x40102dn],
      [0x401040n, 0x401058n, 0n, 3n, 0x40104dn],
      [0x401060n, 0x401078n, 0n, 3n, 0x40106dn],
      [0x401080n, 0x401098n, 0n, 0n, 0x40108dn]
    ]);
    const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
      riscExceptionMap, "nt-risc32", 0x400000n, machine);

    assert.deepEqual(parsed.powerPcCodeSignificance, [1, 1, 2]);
    assert.deepEqual(parsed.issues, []);
    assert.equal(parsed.functionCount, 5);
    assert.equal(parsed.handlerUnwindInfoCount, 0);
    assert.deepEqual(parsed.handlerRvas, []);
    assert.deepEqual(parsed.riscPrologs, { count: 5, empty: 0, minimumBytes: 12, maximumBytes: 12 });
  });
}

void test("PowerPC code markers are not interpreted when an actual handler exists", async () => {
  const source = riscExceptionRows([[0x401000n, 0x401040n, 0x401100n, 3n, 0x401010n],
    [0x401040n, 0x401080n, 0x401100n, 0x401110n, 0x401050n],
    [0x401080n, 0x4010c0n, 0n, 4n, 0x401090n]]);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc32", 0x400000n, 0x1f0);

  assert.equal(parsed.powerPcCodeSignificance, undefined);
  assert.deepEqual(parsed.handlerRvas, [0x1100]);
  assert.equal(parsed.handlerUnwindInfoCount, 2);
  assert.deepEqual(parsed.issues, ["NT RISC handler data VA could not be mapped."]);
});

for (const machine of [undefined, 0x166, 0x184, 0x284]) {
  void test(`Other NT RISC machine ${machine} keeps ordinary handler-data validation`, async () => {
    const source = riscExceptionRows([[0x401000n, 0x401040n, 0n, 3n, 0x401010n]]);
    const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
      riscExceptionMap, "nt-risc32", 0x400000n, machine);

    assert.equal(parsed.powerPcCodeSignificance, undefined);
    assert.deepEqual(parsed.issues, ["NT RISC handler data VA could not be mapped."]);
  });
}

void test("PowerPC code significance is limited to its 32-bit ABI", async () => {
  const source = riscExceptionRows([[0x401000n, 0x401040n, 0n, 3n, 0x401010n]], 8);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc64", 0x400000n, 0x1f0);

  assert.equal(parsed.powerPcCodeSignificance, undefined);
  assert.deepEqual(parsed.issues, ["NT RISC handler data VA could not be mapped."]);
});

void test("PowerPC keeps EM tag diagnostics separate from code significance", async () => {
  const source = riscExceptionRows([[0x401000n, 0x401040n, 1n, 3n, 0x401010n],
    [0x401040n, 0x401080n, 2n, 2n, 0x401050n]]);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc32", 0x400000n, 0x1f0);

  assert.deepEqual(parsed.powerPcCodeSignificance, [0, 1, 1]);
  assert.deepEqual(parsed.riscExceptionModes, [1, 0, 0, 0, 1, 0, 0, 0]);
  assert.deepEqual(parsed.issues, ["Unknown NT RISC handler address tag bit 1 is set."]);
});
