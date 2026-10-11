"use strict";

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { parsePe, isPeWindowsParseResult } from "../../analyzers/pe/index.js";
import { getPeExportDisplayName } from "../../analyzers/pe/directories/export-names.js";
import { createVisualStudioStep, runStep } from "../../scripts/pe-disassembly-samples/command.js";
import { discoverToolchains } from "../../scripts/pe-disassembly-samples/toolchains.js";

const source = `
namespace demo {
__declspec(dllexport) int increment(int value) { return value + 1; }
__declspec(dllexport) int value = 7;
template <class Value> Value square(Value value) { return value * value; }
template __declspec(dllexport) int square<int>(int);
class __declspec(dllexport) Widget {
public:
    Widget();
    int method() const;
};
Widget::Widget() = default;
int Widget::method() const { return value; }
}
extern "C" __declspec(dllexport) int PlainExport(int value) { return value; }
`;

for (const architecture of ["x86", "x64"] as const) {
  void test(`MSVC ${architecture} DLL exports retain raw names and receive LLVM signatures`, async context => {
    if (process.platform !== "win32") return context.skip("MSVC fixture requires Windows.");
    const visualStudio = (await discoverToolchains()).visualStudio;
    if (!visualStudio) return context.skip("Visual Studio C++ Build Tools are not installed.");
    const directory = await mkdtemp(join(tmpdir(), "binary101-msvc-exports-"));
    try {
      const sourcePath = join(directory, "exports.cpp");
      const dllPath = join(directory, "exports.dll");
      await writeFile(sourcePath, source);
      const result = await runStep(createVisualStudioStep("compile", visualStudio, architecture, [[
        "cl.exe", sourcePath, "/nologo", "/std:c++20", "/O2", "/LD", "/EHsc", "/MD",
        `/Fo:${join(directory, "exports.obj")}`, `/Fe:${dllPath}`,
        "/link", `/IMPLIB:${join(directory, "exports.lib")}`, "/DYNAMICBASE", "/INCREMENTAL:NO"
      ]]));
      assert.equal(result.code, 0, [result.stdout, result.stderr].join("\n"));

      const pe = await parsePe(new File([await readFile(dllPath)], "exports.dll"));

      assert.ok(pe && isPeWindowsParseResult(pe) && pe.exports);
      assert.deepEqual(pe.exports.issues, []);
      const names = pe.exports.entries.flatMap(entry => entry.names.map((_name, index) =>
        getPeExportDisplayName(entry.names, index)
      ));
      assert.ok(names.includes("int __cdecl demo::increment(int)"));
      assert.ok(names.includes("int __cdecl demo::square<int>(int)"));
      assert.ok(names.includes("int demo::value"));
      assert.ok(names.includes("PlainExport"));
      assert.ok(names.some(name => name.includes("demo::Widget::Widget(void)")));
      assert.ok(names.some(name => name.includes("demo::Widget::method(void) const")));
      assert.ok(pe.exports.entries.some(entry => entry.names.includes("?increment@demo@@YAHH@Z")));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}
