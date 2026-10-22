import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseExceptionDebugInfo } from "../../analyzers/pe/debug/exception.js";
import { parseExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import { MockFile } from "../helpers/mock-file.js";

// Unchanged clang 22.1.6 AArch64 output from pe-debug-native/ExceptionArm.c,
// linked by lld-link. The executable is never run. Only the appended copy is
// synthetic placement; its .pdata bytes and referenced image bytes are unchanged.
void test("ARM64 raw debug copy without an origin matches its real image table and LLVM", async () => {
  const path = "scan-results/pe-debug-native/raw-exception-arm64.exe";
  const file = new MockFile(await readFile(path));
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const directory = core.dataDirs.find(entry => entry.name === "EXCEPTION");
  assert.ok(directory);
  const offset = core.rvaToOff(directory.rva);
  assert.ok(offset != null);
  const copy = new MockFile(Uint8Array.from([...file.data, ...file.data.subarray(offset, offset + directory.size)]));
  const actual = await parseExceptionDebugInfo(copy, core.rvaToOff, 0, file.size,
    directory.size, core.coff.Machine, assert.fail);
  const expected = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--unwind", path], { encoding: "utf8" });

  assert.ok(expected);
  assert.deepEqual(actual, expected);
  assert.equal(actual?.functionCount, [...oracle.matchAll(/RuntimeFunction \{/g)].length);
  assert.deepEqual(actual?.rangeLengths,
    [...oracle.matchAll(/FunctionLength: (\d+)/g)].map(match => Number(match[1])));
});
