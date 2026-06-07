"use strict";

import type { SampleSummary, SuccessfulSampleResult } from "./model.js";

interface BinarySizeRow {
  arch: string;
  compiler: string;
  language: string;
  mode: string;
  runtimeLinkage: string;
  sizeBytes: number;
  sizeKib: string;
  variantId: string;
}

const splitMode = (id: string, prefix: string): string =>
  id.slice(prefix.length).replace(/-/gu, " ");

const architectureLabel = (value: string): string =>
  value === "amd64" || value === "x64" || value === "win-x64" ? "x64" : "x86";

const nativeRuntimeLinkage = (compiler: string, mode: string): string => {
  if (compiler === "MSVC cl.exe" || compiler === "LLVM clang-cl") {
    return mode.includes("mt") ? "static MSVC CRT" : "DLL MSVC CRT";
  }
  if (compiler === "LLVM clang/clang++ MSVC") return "DLL MSVC CRT";
  if (compiler === "MSYS2 UCRT64 GCC/G++" || compiler === "MSYS2 UCRT64 clang/clang++") {
    return "MSYS2 UCRT DLLs";
  }
  if (compiler === "MSYS2 CLANG64 clang/clang++") return "MSYS2 CLANG64 DLLs";
  return "Zig libc bundled";
};

const describeNative = (result: SuccessfulSampleResult): BinarySizeRow | null => {
  const match = /^(c|cpp)-(.+?)-(x64|x86)-(.+)$/u.exec(result.id);
  if (!match) return null;
  const [, language, family, arch, rawMode] = match;
  if (!language || !family || !arch || !rawMode) return null;
  const compilerByFamily = new Map([
    ["msvc", "MSVC cl.exe"],
    ["clang-cl", "LLVM clang-cl"],
    ["llvm-clang-msvc", "LLVM clang/clang++ MSVC"],
    ["msys-clang64", "MSYS2 CLANG64 clang/clang++"],
    ["msys-ucrt64-clang", "MSYS2 UCRT64 clang/clang++"],
    ["msys-ucrt64", "MSYS2 UCRT64 GCC/G++"],
    ["zig-cc", "Zig cc/c++"]
  ]);
  const compiler = compilerByFamily.get(family);
  if (!compiler) return null;
  const mode = rawMode;
  return makeRow(result, language, arch, compiler, mode, nativeRuntimeLinkage(compiler, mode));
};

const describeCsharp = (result: SuccessfulSampleResult): BinarySizeRow | null => {
  const match = /^csharp-(.+)-(win-x64|win-x86)-release$/u.exec(result.id);
  if (!match) return null;
  const [, flavor, runtime] = match;
  if (!flavor || !runtime) return null;
  const runtimeLinkageByFlavor = new Map([
    ["framework", ".NET runtime external + app DLL"],
    ["readytorun-singlefile", ".NET runtime external single-file"],
    ["readytorun-selfcontained-singlefile", ".NET runtime bundled single-file"],
    ["selfcontained", ".NET runtime files adjacent"],
    ["nativeaot", "NativeAOT self-contained"]
  ]);
  return makeRow(
    result,
    "csharp",
    architectureLabel(runtime),
    ".NET publish",
    `${flavor.replace(/-/gu, " ")} release`,
    runtimeLinkageByFlavor.get(flavor) ?? ".NET publish"
  );
};

const describeRust = (result: SuccessfulSampleResult): BinarySizeRow | null => {
  const match = /^rust-(x64|x86)-(gnu|gnullvm|msvc)-(.+)$/u.exec(result.id);
  if (!match) return null;
  const [, arch, abi, mode] = match;
  if (!arch || !abi || !mode) return null;
  const runtimeLinkageByAbi = new Map([
    ["gnu", "Rust std static + Windows/UCRT DLLs"],
    ["gnullvm", "Rust std static + libunwind/UCRT DLLs"],
    ["msvc", "Rust std static + MSVC/UCRT DLLs"]
  ]);
  return makeRow(result, "rust", arch, `rustc ${abi.toUpperCase()}`, mode, runtimeLinkageByAbi.get(abi)!);
};

const describeGo = (result: SuccessfulSampleResult): BinarySizeRow | null => {
  const match = /^go-windows-(amd64|386)-(.+)$/u.exec(result.id);
  if (!match) return null;
  const [, arch, mode] = match;
  return arch && mode ? makeRow(result, "go", architectureLabel(arch), "Go gc", mode, "Go runtime bundled") : null;
};

const describeOther = (result: SuccessfulSampleResult): BinarySizeRow | null => {
  if (result.id.startsWith("assembly-")) return describeAssembly(result);
  if (result.id.startsWith("pascal-fpc-win32-")) {
    return makeRow(result, "pascal", "x86", "Free Pascal", splitMode(result.id, "pascal-fpc-win32-"), "FPC runtime bundled");
  }
  if (result.id.startsWith("d-dmd-")) return describeD(result);
  if (result.id.startsWith("zig-")) return describeZig(result);
  return null;
};

const describeAssembly = (result: SuccessfulSampleResult): BinarySizeRow | null => {
  const match = /^assembly-(nasm|masm)-(x64|x86)-(.+)$/u.exec(result.id);
  if (!match) return null;
  const [, assembler, arch, mode] = match;
  if (!assembler || !arch || !mode) return null;
  return makeRow(
    result,
    "assembly",
    arch,
    assembler === "nasm" ? "NASM + lld-link" : "MASM + link.exe",
    mode,
    "WinAPI DLL imports"
  );
};

const describeD = (result: SuccessfulSampleResult): BinarySizeRow | null => {
  const mode = splitMode(result.id, "d-dmd-");
  return makeRow(result, "d", mode.startsWith("x86") ? "x86" : "x64", "DMD", mode, "D runtime bundled");
};

const describeZig = (result: SuccessfulSampleResult): BinarySizeRow | null => {
  const match = /^zig-(x64|x86)-(.+)$/u.exec(result.id);
  if (!match) return null;
  const [, arch, mode] = match;
  return arch && mode ? makeRow(result, "zig", arch, "Zig build-exe", mode, "Zig runtime bundled") : null;
};

const makeRow = (
  result: SuccessfulSampleResult,
  language: string,
  arch: string,
  compiler: string,
  mode: string,
  runtimeLinkage: string
): BinarySizeRow => ({
  arch,
  compiler,
  language,
  mode,
  runtimeLinkage,
  sizeBytes: result.outputSize,
  sizeKib: (result.outputSize / 1024).toFixed(1),
  variantId: result.id
});

const describeSuccess = (result: SuccessfulSampleResult): BinarySizeRow =>
  describeNative(result) ?? describeCsharp(result) ?? describeRust(result) ??
  describeGo(result) ?? describeOther(result) ??
  makeRow(result, result.language, "unknown", "unknown", result.label, "unknown");

const renderRow = (row: BinarySizeRow): string =>
  `| ${row.language} | ${row.arch} | ${row.compiler} | ${row.mode} | ${row.runtimeLinkage} | ` +
  `${row.sizeBytes} | ${row.sizeKib} | ${row.variantId} |`;

export const buildBinarySizeMarkdown = (summary: SampleSummary): string => {
  const rows = summary.results
    .filter((result): result is SuccessfulSampleResult => result.kind === "success")
    .map(describeSuccess);
  return [
    "# PE Disassembly Sample Binary Sizes",
    "",
    "Generated from `summary.json` by `scripts/pe-disassembly-samples/size-table.ts`.",
    "",
    "The build pipeline validates primary PE outputs before they enter `summary.json`.",
    "Those outputs should have no COFF symbol records in the executable.",
    "The authentic Go internal linker may leave an empty COFF pointer with zero records.",
    "Adjacent PDB files may still exist for toolchains that emit them.",
    "",
    "| language | arch | compiler | mode | runtime linkage | size bytes | size KiB | variant id |",
    "|---|---|---|---|---|---:|---:|---|",
    ...rows.map(renderRow),
    ""
  ].join("\n");
};
