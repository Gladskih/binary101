"use strict";

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { parsePe, isPeWindowsParseResult } from "../../analyzers/pe/index.js";
import { getImportFunctionDisplayName } from "../../analyzers/pe/imports/function-name.js";
import { createVisualStudioStep, runStep } from "../../scripts/pe-disassembly-samples/command.js";
import { discoverToolchains } from "../../scripts/pe-disassembly-samples/toolchains.js";

for (const architecture of ["x86", "x64"] as const) {
  for (const mode of ["eager", "delay"]) {
    void test(`MSVC ${architecture} ${mode} imports retain linker names and LLVM signatures`, async context => {
      if (process.platform !== "win32") return context.skip("MSVC fixture requires Windows.");
      const visualStudio = (await discoverToolchains()).visualStudio;
      if (!visualStudio) return context.skip("Visual Studio C++ Build Tools are not installed.");
      const directory = await mkdtemp(join(tmpdir(), "binary101-msvc-imports-"));
      try {
        await writeFile(join(directory, "library.cpp"),
          "namespace demo { __declspec(dllexport) int increment(int v) { return v + 1; } }");
        await writeFile(join(directory, "client.cpp"),
          "namespace demo { __declspec(dllimport) int increment(int); }\n" +
          "int main() { return demo::increment(1); }");
        const result = await runStep(createVisualStudioStep("compile", visualStudio, architecture, [
          ["cl.exe", join(directory, "library.cpp"), "/nologo", "/O2", "/LD", "/MD",
            `/Fo:${join(directory, "library.obj")}`, `/Fe:${join(directory, "library.dll")}`,
            "/link", `/IMPLIB:${join(directory, "library.lib")}`, "/INCREMENTAL:NO"],
          ["cl.exe", join(directory, "client.cpp"), "/nologo", "/O2", "/MD",
            `/Fo:${join(directory, "client.obj")}`, `/Fe:${join(directory, "client.exe")}`,
            "/link", join(directory, "library.lib"), "/INCREMENTAL:NO",
            ...(mode === "delay" ? ["/DELAYLOAD:library.dll", "delayimp.lib"] : [])]
        ]));
        assert.equal(result.code, 0, [result.stdout, result.stderr].join("\n"));

        const pe = await parsePe(new File([await readFile(join(directory, "client.exe"))], "client.exe"));

        assert.ok(pe && isPeWindowsParseResult(pe));
        const functions = mode === "eager"
          ? pe.imports.entries.find(entry => entry.dll === "library.dll")?.functions
          : pe.delayImports?.entries.find(entry => entry.name === "library.dll")?.functions;
        assert.ok(functions);
        assert.equal(functions[0]?.name, "?increment@demo@@YAHH@Z");
        assert.equal(getImportFunctionDisplayName(functions[0]!), "int __cdecl demo::increment(int)");
        assert.equal(pe.imports.warning, undefined);
        assert.equal(pe.delayImports?.warning, undefined);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    });
  }
}
