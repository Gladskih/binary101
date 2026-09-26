import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parsePe, isPeWindowsParseResult } from "../../analyzers/pe/index.js";
import type { DModuleInfo } from "../../analyzers/d-runtime/types.js";
import { createFileRangeReader, type FileRangeReader } from "../../analyzers/file-range-reader.js";
import { parsePeHeaders, isPeWindowsCore } from "../../analyzers/pe/core/index.js";
import { parseBaseRelocations, type PeBaseRelocationResult } from "../../analyzers/pe/directories/reloc.js";
import type { PeWindowsCore } from "../../analyzers/pe/types.js";
import { analyzePeDRuntime } from "../../analyzers/pe/d-runtime.js";
import {
  buildDRuntimeProgram, hasWindowsDCompiler, renameDRuntimePeSections
} from "../fixtures/d-runtime-program.js";
import { D_TEST_ABI, D_TEST_IO } from "../fixtures/d-runtime.js";

const checkBuiltImage = async (directory: string, flags: string[]): Promise<void> => {
  const built = await buildDRuntimeProgram(directory, flags);
  const parsed = await parsePe(new File([built.bytes], "sample.exe"));
  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.ok(parsed.dRuntime);
  assert.deepEqual(parsed.dRuntime.warnings, []);
  assert.equal(parsed.dRuntime.modules.length, built.modules.length);
  for (const [name, flagsValue, imports, classes] of built.modules) {
    const module: DModuleInfo | undefined =
      parsed.dRuntime.modules.find(candidate => candidate.name === name);
    assert.ok(module, name);
    assert.equal(module.flags & ~(D_TEST_ABI.flags.constructorStarted | D_TEST_ABI.flags.constructorDone),
      Number(flagsValue), name);
    assert.equal(module.importedModules.length, Number(imports), name);
    assert.equal(module.localClasses.length, Number(classes), name);
  }
  renameDRuntimePeSections(built.bytes, parsed);
  const renamed = await parsePe(new File([built.bytes], "renamed.exe"));
  assert.ok(renamed && isPeWindowsParseResult(renamed));
  assert.deepEqual(renamed.dRuntime, parsed.dRuntime);
};

void test("D PE metadata matches druntime in PE32, PE32+ and optimized builds", async context => {
  if (!(await hasWindowsDCompiler())) return context.skip("Windows DMD toolchain is not installed");
  const directory = await mkdtemp(join(tmpdir(), "binary101-d-runtime-test-"));
  try {
    await checkBuiltImage(directory, ["-m64"]);
    await checkBuiltImage(directory, ["-m32mscoff"]);
    await checkBuiltImage(directory, ["-m64", "-O", "-release", "-inline"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

const measureDiscovery = async (file: Blob, reader: FileRangeReader, core: PeWindowsCore,
  relocations: PeBaseRelocationResult | null) => {
  const read = reader.read;
  let readCount = 0;
  reader.read = async (offset, size) => {
    assert.ok(size <= D_TEST_IO.readWindowBytes, "Each sparse read must fit one reader window");
    readCount += 1;
    return read(offset, size);
  };
  // Repeat against a warm cache to measure CPU overhead; do not assert a flaky time threshold.
  const iterations = 100;
  const start = performance.now();
  for (let iteration = 0; iteration < iterations; iteration += 1) {
    assert.equal(await analyzePeDRuntime(file, reader, core, relocations), null);
  }
  return `${((performance.now() - start) / iterations).toFixed(3)} ms, ` +
    `${readCount / iterations} reader calls per D probe`;
};

for (const name of ["kernel32.dll", "ntdll.dll", "user32.dll", "cmd.exe", "notepad.exe"]) {
  void test(`D discovery remains bounded and rejects ordinary ${name}`, async context => {
    if (process.platform !== "win32") return context.skip("Requires Windows system images");
    const file = new File([await readFile(join(process.env["SystemRoot"] ?? "C:/Windows",
      "System32", name))], name);
    const reader = createFileRangeReader(file, 0, file.size);
    const core = await parsePeHeaders(reader);
    assert.ok(core && isPeWindowsCore(core));
    context.diagnostic(`${name}: ${await measureDiscovery(file, reader, core,
      await parseBaseRelocations(reader, core.dataDirs, core.rvaToOff))}`);
  });
}
