import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { isPeWindowsParseResult, parsePe } from "../../analyzers/pe/index.js";
import { MockFile } from "../helpers/mock-file.js";

const compiler = process.env["MINGW_CXX"] ?? "C:/msys64/ucrt64/bin/g++.exe";
for (const optimization of ["-O0", "-O2"]) {
  void test(`recognizes real stripped static MinGW RTTI (${optimization})`, {
    skip: !existsSync(compiler)
  }, async () => {
    const directory = await mkdtemp(join(tmpdir(), "binary101-itanium-"));
    try {
      const executable = join(directory, "fixture.exe");
      execFileSync(compiler, [resolve("samples/pe-disassembly/cpp/itanium-rtti.cpp"),
        "-o", executable, optimization, "-static", "-s", "-Wl,--dynamicbase"], {
        env: { ...process.env, PATH: dirname(compiler) + ";" + process.env["PATH"] }
      });
      const parsed = await parsePe(new MockFile(await readFile(executable)));
      assert.ok(parsed && isPeWindowsParseResult(parsed));
      assert.ok(parsed.itaniumRtti);
      const types = new Map(parsed.itaniumRtti.types.map(type => [type.name, type]));
      assert.equal(types.get("4Base")?.kind, "class");
      assert.equal(types.get("7Derived")?.kind, "si");
      assert.equal(types.get("8Multiple")?.bases.length, 2);
      assert.equal(types.get("7Virtual")?.bases[0]?.isVirtual, true);
      assert.deepEqual(parsed.itaniumRtti.warnings, []);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}
