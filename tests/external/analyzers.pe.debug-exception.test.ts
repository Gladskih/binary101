import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseExceptionDebugInfo } from "../../analyzers/pe/debug/exception.js";
import { parseExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import { MockFile } from "../helpers/mock-file.js";

// The records and referenced unwind data come from an unchanged Windows DLL.
// Only the separate raw .pdata copy is constructed; this does not claim a natural
// IMAGE_DEBUG_TYPE_EXCEPTION entry in kernel32.dll.
void test("raw-only copy of real Windows .pdata agrees with the image table and LLVM", async () => {
  const path = "C:/Windows/System32/kernel32.dll";
  const file = new MockFile(await readFile(path));
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const directory = core.dataDirs.find(entry => entry.name === "EXCEPTION");
  assert.ok(directory);
  const offset = core.rvaToOff(directory.rva);
  assert.ok(offset != null);
  const copy = new MockFile(Uint8Array.from([...file.data, ...file.data.subarray(offset, offset + directory.size)]));
  const warnings: string[] = [];
  const actual = await parseExceptionDebugInfo(copy, core.rvaToOff, 0, file.size,
    directory.size, core.coff.Machine, warning => warnings.push(warning), directory);
  const expected = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const llvm = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--unwind", path],
    { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });

  assert.ok(expected && expected.functionCount > 0);
  assert.ok(actual, warnings.join(" | "));
  assert.deepEqual(actual, expected);
  assert.equal(actual.functionCount, [...llvm.matchAll(/RuntimeFunction \{/g)].length);
  assert.deepEqual(warnings, []);
});
