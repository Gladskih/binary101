import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../analyzers/pe/debug/directory.js";
import { buildCodeViewArrayBounds } from "../../renderers/pe/codeview-array-bounds.js";
import { MockFile } from "../helpers/mock-file.js";

// Official 2026-10-01-Build Fortran archive, SHA256
// 31b9922dc3a9f6143faf590d4fef532cdc2cdb424c177b4d58192fffc992b3c6.
// The 32-bit host works here; the archive's 64-bit compiler crashes before producing an object.
const compileFortran = async (): Promise<string> => {
  const directory = resolve("scan-results/pe-debug-native/fortran-reference");
  const distribution = resolve("scan-results/openwatcom-20261001");
  await mkdir(directory, { recursive: true });
  await copyFile(resolve("tests/external/pe-debug-native/ArrayBounds.for"), resolve(directory, "ArrayBounds.for"));
  const options = { cwd: directory, env: { ...process.env, WATCOM: distribution } };
  execFileSync(resolve(distribution, "binnt/wfc386.exe"), ["-d2", "-hc", "-fo=ArrayBounds.obj", "ArrayBounds.for"], options);
  execFileSync(resolve(distribution, "binnt/wlink.exe"), ["debug", "codeview", "all", "format", "windows", "nt", "dll",
    "libpath", resolve(distribution, "lib386/nt"), "libpath", resolve(distribution, "lib386"),
    "library", "kernel32,user32", "name", "ArrayBounds.dll", "file", "ArrayBounds.obj"], options);
  return resolve(directory, "ArrayBounds.dll");
};

void test("unchanged Open Watcom Fortran emits exact fixed bounds and four referenced variable bounds", async () => {
  const file = new MockFile(await readFile(await compileFortran()));
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const info = debug.entries.find(entry => entry.legacyCodeView)?.legacyCodeView;
  assert.ok(info);
  assert.equal(info.signature, "NB05");
  const records = info.directories.flatMap(directory => directory.subsections)
    .flatMap(section => section.data?.kind === "types" ? section.data.records : []);
  assert.deepEqual(records.filter(record => record.shape?.kind === "constantDimensions").map(record => record.shape), [
    { kind: "constantDimensions", rank: 2, indexType: 0x74, boundKind: "lowerUpper",
      bounds: { kind: "integers", values: ["-1", "3", "2", "5"] } }
  ]);
  const variable = records.find(record => record.shape?.kind === "variableDimensions")?.shape;
  assert.ok(variable?.kind === "variableDimensions");
  assert.equal(variable.rank, 2);
  assert.equal(variable.indexType, 0x74);
  assert.equal(variable.boundKind, "lowerUpper");
  assert.equal(variable.bounds.length, 4);
  const indexed = new Map(records.map(record => [record.index, record]));
  assert.deepEqual(variable.bounds.map(index => indexed.get(index)?.symbols?.map(symbol => symbol.name)),
    [["__bck"], ["__bck"], ["__bck"], ["__bck"]]);
  assert.deepEqual(buildCodeViewArrayBounds(info)[0]?.rows.map(row => row.slice(3)), [
    ["int32", "1", "-1", "3"], ["int32", "2", "2", "5"],
    ["int32", "1", "__bck", "__bck"], ["int32", "2", "__bck", "__bck"]
  ]);
  // NB05 also has one runtime-library public aggregate with repeated signatures;
  // retain its existing symbol warning, but no type/bounds warnings are expected.
  assert.equal(debug.warning, "Debug entry #2: Error: Invalid CodeView symbol record length.");
});
