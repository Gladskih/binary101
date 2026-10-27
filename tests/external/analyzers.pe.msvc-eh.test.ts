import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parsePeHeaders, isPeWindowsCore } from "../../analyzers/pe/core/index.js";
import { parseExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import { selectPeVariantParsers } from "../../analyzers/pe/parse-variant.js";
import { analyzeMsvcEh } from "../../analyzers/pe/msvc-eh/index.js";
import { collectEhLoadConfigChecks } from "../../analyzers/pe/msvc-eh/checks.js";
import { parseExportDirectory } from "../../analyzers/pe/directories/exports.js";
import { MockFile } from "../helpers/mock-file.js";

// These opt-in Windows integration tests build images but never execute them.
// The host MSVC supplies ehdata{,4_export}.h and genuine CRT import libraries.
const msvc = "C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Tools/MSVC/14.51.36231";
const lld = "C:/Program Files/LLVM/bin/lld-link.exe";
const source = (name: string): string => resolve("tests/external/pe-debug-native", name);
const output = (name: string): string => resolve("scan-results/pe-msvc-eh", name);

const parseImage = async (path: string) => {
  const file = new MockFile(await readFile(path));
  const core = await parsePeHeaders(file);
  assert.ok(core && isPeWindowsCore(core));
  const variant = selectPeVariantParsers(core.opt.Magic, core.coff.Machine);
  const exception = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const imports = await variant.parseImportDirectory(file, core.dataDirs, core.rvaToOff);
  const exports = await parseExportDirectory(file, core.dataDirs, core.rvaToOff);
  const loadConfig = await variant.parseAndEnrichLoadConfig(file, core.dataDirs, core.rvaToOff,
    core.opt.ImageBase, core.opt.SizeOfImage, core.opt.SizeOfHeaders, core.sections);
  return { core, exception, loadConfig,
    analysis: await analyzeMsvcEh(file, core, exception, imports, exports?.entries ?? [], loadConfig) };
};

const buildMsvc = async (name: string, architecture: "x64" | "x86", options: string[],
  linkOptions: string[] = [], linker = lld) => {
  await mkdir(output("."), { recursive: true });
  const compiler = `${msvc}/bin/Hostx64/${architecture}/cl.exe`;
  execFileSync(compiler, ["/nologo", "/c", "/EHsc", "/GS-", "/MD", "/O2", ...options,
    `/Fo${output(`${name}.obj`)}`, source("MsvcEh.cpp")]);
  execFileSync(compiler, ["/nologo", "/c", "/GS-", "/MD", "/O2",
    `/Fo${output(`${name}-sink.obj`)}`, source("MsvcEhSink.cpp")]);
  execFileSync(linker, ["/dll", "/noentry", "/nodefaultlib", ...linkOptions, `/out:${output(`${name}.dll`)}`,
    `/include:${architecture === "x86" ? "__load_config_used" : "_load_config_used"}`,
    `/libpath:${msvc}/lib/${architecture}`,
    `/libpath:C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/ucrt/${architecture}`,
    output(`${name}.obj`), output(`${name}-sink.obj`), "vcruntime.lib", "msvcrt.lib", "ucrt.lib"]);
  return parseImage(output(`${name}.dll`));
};

for (const [name, architecture, options, version] of [
  ["msvc-fh3", "x64", ["/d2FH4-"], 3],
  ["msvc-fh4", "x64", [], 4],
  ["msvc-x86", "x86", [], 3]
] as const) {
  void test(`${name} compiler output exposes both int and ellipsis catches`, async () => {
    const parsed = await buildMsvc(name, architecture, [...options]);
    assert.ok(parsed.analysis?.records.length);
    assert.equal(parsed.analysis.records[0]?.functionInfo?.version, version);
    assert.equal(parsed.analysis.records[0]?.functionInfo?.tryBlocks[0]?.handlers.length, 2);
    assert.deepEqual(parsed.analysis.warnings, []);
    const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe",
      ["--unwind", "--coff-imports", output(`${name}.dll`)]).toString();
    assert.match(oracle, new RegExp(`__CxxFrameHandler${version}`));
  });
}

void test("MSVC EHCONT contains the explicit FH4 continuations decoded independently", async () => {
  const parsed = await buildMsvc("msvc-fh4-ehcont", "x64", ["/guard:ehcont", "/guard:cf"],
    ["/guard:ehcont", "/guard:cf"], `${msvc}/bin/Hostx64/x64/link.exe`);
  assert.ok(parsed.analysis && parsed.loadConfig);
  assert.deepEqual(parsed.analysis.warnings, []);
  assert.ok(parsed.analysis.records[0]?.functionInfo?.tryBlocks.some(block =>
    block.handlers.some(handler => handler.continuationRvas.length > 0)));
  const checks = collectEhLoadConfigChecks(parsed.loadConfig, parsed.analysis, parsed.core.opt.DllCharacteristics);
  assert.equal(checks.find(check => check.title === "Microsoft EH continuation targets")?.status, "pass");
});

void test("Clang ARM64 FH3 matches LLVM's runtime and handler inventory", async () => {
  await mkdir(output("."), { recursive: true });
  const clang = "C:/Program Files/LLVM/bin/clang-cl.exe";
  execFileSync(clang, ["--target=aarch64-pc-windows-msvc", "/c", "/EHsc", "/GS-", "/Od",
    "/DEH_CATCH_ALL_ONLY", `/Fo${output("arm64.obj")}`, source("MsvcEh.cpp")]);
  execFileSync(clang, ["--target=aarch64-pc-windows-msvc", "/c", "/GS-",
    `/Fo${output("arm64-sink.obj")}`, source("MsvcEhSink.cpp")]);
  execFileSync(lld, ["/lib", "/machine:arm64", `/def:${source("MsvcEhRuntime.def")}`,
    `/out:${output("arm64-runtime.lib")}`]);
  execFileSync(lld, ["/dll", "/noentry", "/nodefaultlib", `/out:${output("arm64.dll")}`,
    output("arm64.obj"), output("arm64-sink.obj"), output("arm64-runtime.lib")]);
  const parsed = await parseImage(output("arm64.dll"));
  assert.ok(parsed.analysis?.records.length);
  assert.deepEqual(parsed.analysis.warnings, []);
  assert.equal(parsed.analysis.records[0]?.functionInfo?.version, 3);
  assert.equal(parsed.analysis.records[0]?.functionInfo?.tryBlocks[0]?.handlers.length, 1);
});

void test("ARMNT assembler emits a linked relative FH3 graph with Thumb targets", async () => {
  await mkdir(output("."), { recursive: true });
  execFileSync("C:/msys64/clang64/bin/llvm-mc.exe", ["-triple=thumbv7-pc-windows-msvc", "-filetype=obj",
    source("MsvcEhArmnt.s"), "-o", output("armnt.obj")]);
  execFileSync(lld, ["/lib", "/machine:arm", `/def:${source("MsvcEhRuntime.def")}`,
    `/out:${output("armnt-runtime.lib")}`]);
  execFileSync(lld, ["/dll", "/noentry", "/nodefaultlib", `/out:${output("armnt.dll")}`,
    output("armnt.obj"), output("armnt-runtime.lib")]);
  const parsed = await parseImage(output("armnt.dll"));
  assert.equal(parsed.analysis?.records[0]?.functionInfo?.version, 3);
  assert.deepEqual(parsed.analysis?.warnings, []);
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe",
    ["--unwind", output("armnt.dll")]).toString();
  assert.match(oracle, /ExceptionData: Yes/);
  assert.equal(parsed.exception?.languageHandlers?.length, [...oracle.matchAll(/ExceptionHandler \[/g)].length);
});

for (const [name, gsOption, exports, handlerName] of [
  ["seh", "/GS-", [], "__C_specific_handler"],
  ["seh-gs", "/GS", ["/export:__GSHandlerCheck_SEH"], "__GSHandlerCheck_SEH"]
] as const) {
  void test(`MSVC ${name} scopes validate against their .pdata owner and EHCONT table`, async () => {
    await mkdir(output("."), { recursive: true });
    execFileSync(`${msvc}/bin/Hostx64/x64/cl.exe`, ["/nologo", "/c", gsOption, "/Od", "/MD",
      "/guard:ehcont", "/guard:cf", "/FAs", `/Fa${output(`${name}.asm`)}`,
      `/Fo${output(`${name}.obj`)}`, source("MsvcSeh.c")]);
    execFileSync(`${msvc}/bin/Hostx64/x64/link.exe`, ["/dll", "/noentry", "/nodefaultlib",
      "/guard:ehcont", "/guard:cf", "/include:_load_config_used", ...exports,
      `/out:${output(`${name}.dll`)}`, `/libpath:${msvc}/lib/x64`,
      "/libpath:C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/ucrt/x64",
      output(`${name}.obj`), "vcruntime.lib", "msvcrt.lib", "ucrt.lib"]);
    const parsed = await parseImage(output(`${name}.dll`));
    assert.ok(parsed.analysis?.records[0]?.scopes?.length);
    assert.ok(parsed.analysis.records[0].evidence.includes(handlerName));
    assert.deepEqual(parsed.analysis.warnings, []);
    assert.ok(parsed.loadConfig);
    const checks = collectEhLoadConfigChecks(parsed.loadConfig, parsed.analysis, parsed.core.opt.DllCharacteristics);
    assert.equal(checks.find(check => check.title === "Microsoft EH continuation targets")?.status, "pass");
  });
}
