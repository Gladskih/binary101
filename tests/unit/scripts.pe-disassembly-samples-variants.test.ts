"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { MsysToolchain, Toolchains } from "../../scripts/peDisassemblySamples-model.js";
import { buildSampleVariants } from "../../scripts/peDisassemblySamples-variants.js";

const createMsysToolchain = (prefix: string): MsysToolchain => ({
  binDirectory: `${prefix}\\bin`,
  gcc: `${prefix}\\bin\\gcc.exe`,
  gxx: `${prefix}\\bin\\g++.exe`,
  clang: `${prefix}\\bin\\clang.exe`,
  clangxx: `${prefix}\\bin\\clang++.exe`,
  lldLink: `${prefix}\\bin\\lld-link.exe`
});

const createToolchains = (): Toolchains => ({
  clang: "C:\\LLVM\\bin\\clang.exe",
  clangCl: "C:\\LLVM\\bin\\clang-cl.exe",
  dmd: "C:\\D\\dmd2\\windows\\bin64\\dmd.exe",
  dotnet: "C:\\Program Files\\dotnet\\dotnet.exe",
  fpc: "C:\\FPC\\3.2.2\\bin\\i386-win32\\fpc.exe",
  go: "C:\\Program Files\\Go\\bin\\go.exe",
  lldLink: "C:\\LLVM\\bin\\lld-link.exe",
  nasm: "C:\\Users\\me\\bin\\nasm.exe",
  rustc: "C:\\Users\\me\\.cargo\\bin\\rustc.exe",
  rustI686GnuLinker: "C:\\msys64\\mingw32\\bin\\i686-w64-mingw32-gcc.exe",
  rustI686GnullvmLinker: "C:\\msys64\\clang32\\bin\\i686-w64-mingw32-clang.exe",
  visualStudio: {
    installationPath: "C:\\VS",
    vcvarsallPath: "C:\\VS\\VC\\Auxiliary\\Build\\vcvarsall.bat"
  },
  zig: "C:\\zig\\zig.exe",
  msysClang64: createMsysToolchain("C:\\msys64\\clang64"),
  msysUcrt64: createMsysToolchain("C:\\msys64\\ucrt64")
});

void test("buildSampleVariants covers each hello-world source family", () => {
  const variants = buildSampleVariants(createToolchains(), "C:\\out");
  const languages = new Set(variants.map(variant => variant.language));
  const ids = variants.map(variant => variant.id);

  assert.equal(variants.length, 102);
  assert.deepEqual(languages, new Set(["assembly", "c", "cpp", "csharp", "d", "go", "pascal", "rust", "zig"]));
  assert.ok(ids.includes("c-msvc-x64-o2-md"));
  assert.ok(ids.includes("cpp-zig-cc-x86-o2"));
  assert.ok(ids.includes("rust-x64-msvc-o3-panic-abort"));
  assert.ok(ids.includes("go-windows-386-noopt"));
  assert.ok(ids.includes("csharp-nativeaot-win-x64-release"));
  assert.ok(ids.includes("assembly-nasm-x64-lld"));
});

void test("buildSampleVariants keeps missing tools as skipped variants", () => {
  const toolchains = {
    ...createToolchains(),
    nasm: null,
    lldLink: null,
    visualStudio: null
  };
  const variants = buildSampleVariants(toolchains, "C:\\out");
  const nasm = variants.find(variant => variant.id === "assembly-nasm-x64-lld");
  const masm = variants.find(variant => variant.id === "assembly-masm-x64-link");

  assert.match(nasm?.skipReason ?? "", /nasm was not found/);
  assert.match(nasm?.skipReason ?? "", /lld-link was not found/);
  assert.match(masm?.skipReason ?? "", /Visual Studio vcvarsall\.bat was not found/);
});
