import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { parsePeHeaders, isPeWindowsCore } from "../../analyzers/pe/core/index.js";
import { parseTd32Sources } from "../../analyzers/pe/debug/td32-sources.js";
import { MockFile } from "../helpers/mock-file.js";

// Both original artifacts are public at AntonyFFC/arkanoid-game, commit
// 50d66b1b6306b3242f6f2f4cd71b9f75d3ac16e3. The EXE is stripped.
// Appending its unchanged TDS exercises container placement; this is not claimed
// to be a natural compiler-produced embedded-TD32 PE. Neither file is executed.
void test("appended real TD32 retains every upstream-decoded name after a real PE image", async () => {
  const root = resolve("scan-results/td32-public");
  const executable = await readFile(resolve(root, "arkanoid-Project1.exe"));
  const symbols = await readFile(resolve(root, "arkanoid-Project1.tds"));
  const source = new MockFile(Uint8Array.from([...executable, ...symbols]));
  const core = await parsePeHeaders(source);
  assert.ok(core && isPeWindowsCore(core));
  const warnings: string[] = [];
  const parsed = await parseTd32Sources(source, core.sections, core.opt.SizeOfHeaders,
    [], core.rvaToOff, message => warnings.push(message));
  const oracle = JSON.parse(execFileSync(resolve("scan-results/td32-oracle.exe"),
    [resolve("scan-results/td32-upstream.dll"), resolve(root, "arkanoid-Project1.tds")],
    { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 })) as { names: string[] };

  assert.equal(parsed.length, 1);
  assert.equal(parsed[0]?.kind, "overlay");
  assert.equal(parsed[0]?.offset, executable.length);
  assert.equal(parsed[0]?.size, symbols.length);
  assert.deepEqual(parsed[0]?.td32.directories[0]?.subsections.flatMap(section =>
    section.data?.kind === "names" ? section.data.names : []), oracle.names);
  assert.deepEqual(warnings, []);
});
