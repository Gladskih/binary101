import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { MockFile } from "../helpers/mock-file.js";
import { parsePeHeaders, isPeWindowsCore } from "../../analyzers/pe/core/index.js";
import { parseExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import { createIa64DescriptorElf, readGnuIa64Statistics } from "./pe-debug-native/ia64-descriptor-elf.js";

// Microsoft Visual C++ 2010 IA64 redistributable, extracted read-only without running it.
// https://www.microsoft.com/en-us/download/details.aspx?id=21576
// Native SDK API/layout oracle; this is not an independent unwind-payload decoder.
void test("genuine Microsoft IA64 .pdata agrees with Windows SDK and DbgHelp", async () => {
  const path = resolve("scan-results/pe-debug-native/vcredist-ia64-extracted/F_CENTRAL_msvcr100_i64");
  const bytes = await readFile(path);
  assert.equal(createHash("sha256").update(bytes).digest("hex"),
    "e5aa767cfcde7e01460ece68ee0b3d171e44bea1181e8f78d98f92dea4f15e35");
  const oracle = JSON.parse(execFileSync(resolve("scan-results/pe-debug-native/sdk-ia64-pdata.exe"),
    [path], { encoding: "utf8" })) as { entrySize: number; rows: [number, number, number][] };
  const file = new MockFile(bytes);
  const core = await parsePeHeaders(file);
  assert.ok(core && isPeWindowsCore(core));
  const parsed = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);

  assert.equal(core.coff.Machine, 0x200);
  assert.equal(oracle.entrySize, 12);
  assert.equal(oracle.rows.length, 2330);
  assert.equal(parsed?.format, "ia64");
  assert.equal(parsed.functionCount, oracle.rows.length);
  assert.equal(parsed.invalidEntryCount, 0);
  assert.deepEqual(parsed.beginRvas, oracle.rows.map(row => row[0]));
  assert.deepEqual(parsed.rangeLengths, oracle.rows.map(row => row[1] - row[0]));
  assert.equal(parsed.uniqueUnwindInfoCount, new Set(oracle.rows.map(row => row[2])).size);
  assert.equal(parsed.uniqueUnwindInfoCount, 1377);
  assert.deepEqual(parsed.issues, []);
  assert.deepEqual(parsed.ia64Unwind?.versions, [{ version: 3, count: 1377 }]);
  assert.equal(parsed.handlerUnwindInfoCount, 388);
  assert.equal(parsed.ia64Unwind?.exceptionHandlerCount, 248);
  assert.equal(parsed.ia64Unwind?.unwindHandlerCount, 372);
  assert.deepEqual(await readFile(path), bytes);
});

void test("genuine IA64 descriptor summaries agree with unchanged GNU readelf", async () => {
  const path = resolve("scan-results/pe-debug-native/vcredist-ia64-extracted/F_CENTRAL_msvcr100_i64");
  const bytes = await readFile(path);
  const oracle = JSON.parse(execFileSync(resolve("scan-results/pe-debug-native/sdk-ia64-pdata.exe"),
    [path], { encoding: "utf8" })) as { rows: [number, number, number][] };
  const file = new MockFile(bytes);
  const core = await parsePeHeaders(file);
  assert.ok(core && isPeWindowsCore(core));
  await writeFile("scan-results/pe-debug-native/ia64-descriptor-oracle.elf",
    createIa64DescriptorElf(bytes, oracle.rows, core.rvaToOff));
  const root = "/mnt/c/Users/glads/source/binary101-pe-debug/scan-results";
  const output = execFileSync("wsl.exe", ["-d", "Ubuntu-26.04", "--", "env",
    `LD_LIBRARY_PATH=${root}/binutils-multiarch/root/usr/lib/x86_64-linux-gnu`,
    `${root}/binutils-multiarch/root/usr/bin/x86_64-linux-gnu-readelf`, "-u",
    `${root}/pe-debug-native/ia64-descriptor-oracle.elf`], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  const parsed = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);

  assert.match(output, /contains 1377 entries/);
  assert.deepEqual(parsed?.ia64Unwind?.descriptorCounts, readGnuIa64Statistics(output));
  assert.equal(parsed.ia64Unwind?.maximumFixedStackBytes,
    Math.max(...[...output.matchAll(/P7:mem_stack_f\(t=\d+,size=(\d+)\)/g)].map(row => Number(row[1]))));
  assert.equal(parsed.ia64Unwind?.maximumFixedStackBytes, 6864);
  assert.deepEqual(parsed.issues, []);
  assert.deepEqual(await readFile(path), bytes);
});
