import assert from "node:assert/strict";
import { test } from "node:test";
import { writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { createNtRiscPe, createNtRiscSecondaryPe } from "../fixtures/pe-risc-exception.js";
import { parsePeHeaders, isPeWindowsCore } from "../../analyzers/pe/core/index.js";
import { parseExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import { parseDebugDirectory } from "../../analyzers/pe/debug/directory.js";

// Controlled NT .pdata examples, independently decoded by unchanged dumpbin.
// These fixtures are never executed and do not claim to be compiler output.
for (const machine of [0x166, 0x184, 0x1f0, 0x1f1]) {
  void test(`NT RISC ${machine.toString(16)} ranges and prologs agree with Microsoft dumpbin`, async () => {
    const file = createNtRiscPe(machine);
    const path = resolve(`scan-results/pe-debug-native/nt-risc-${machine.toString(16)}.exe`);
    await writeFile(path, file.data);
    const oracle = execFileSync("C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Tools/" +
      "MSVC/14.51.36231/bin/Hostx64/x64/dumpbin.exe", ["/pdata", path], { encoding: "utf8" });
    const core = await parsePeHeaders(file);
    assert.ok(core && isPeWindowsCore(core));
    const parsed = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, machine,
      undefined, undefined, core.opt);
    const copy = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, machine, core.opt);
    const rows = [...oracle.matchAll(/^\s+[0-9A-F]{8} ([0-9A-F]{8}) ([0-9A-F]{8}) [0-9A-F]{8} [0-9A-F]{8} ([0-9A-F]{8}) Primary/gm)];

    assert.ok(parsed);
    assert.match(oracle, /Function Table \(1\)/);
    assert.equal(rows.length, 1);
    assert.equal(parsed.functionCount, rows.length);
    assert.deepEqual(parsed.beginRvas, rows.map(row => Number(BigInt(`0x${row[1]}`) - core.opt.ImageBase)));
    assert.deepEqual(parsed.rangeLengths, rows.map(row => parseInt(row[2]!, 16) - parseInt(row[1]!, 16)));
    assert.equal(parsed.riscPrologs?.maximumBytes, parseInt(rows[0]![3]!, 16) - parseInt(rows[0]![1]!, 16));
    assert.deepEqual(copy.entries[0]!.exception, parsed);
    assert.deepEqual(parsed.issues, []);
    assert.equal(copy.warning, null);
  });
}

void test("Microsoft dumpbin distinguishes secondary type bits from primary handler-data VAs", async () => {
  const file = createNtRiscSecondaryPe();
  const path = resolve("scan-results/pe-debug-native/nt-risc-secondary.exe");
  await writeFile(path, file.data);
  const oracle = execFileSync("C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Tools/" +
    "MSVC/14.51.36231/bin/Hostx64/x64/dumpbin.exe", ["/pdata", path], { encoding: "utf8" });
  const core = await parsePeHeaders(file);
  assert.ok(core && isPeWindowsCore(core));
  const parsed = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine,
    undefined, undefined, core.opt);

  assert.match(oracle, /Function Table \(2\)/);
  assert.match(oracle, /00401040 00401080 00000000 00000003 00401100 3->00000100/);
  assert.equal(parsed?.functionCount, 2);
  assert.equal(parsed?.invalidEntryCount, 0);
  assert.equal(parsed?.riscPrologs?.count, 1);
  assert.equal(parsed?.handlerUnwindInfoCount, 0);
  assert.deepEqual(parsed?.handlerRvas, []);
  assert.deepEqual(parsed?.issues,
    ["NT RISC prolog location is outside its function; indirect prolog metadata is not decoded."]);
});
