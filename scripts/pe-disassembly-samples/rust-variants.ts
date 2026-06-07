"use strict";

import { join } from "node:path";
import { createVisualStudioStep, prependPath } from "./command.js";
import {
  projectRoot,
  type BinarySizeTableColumns,
  type BuildStep,
  type BuildVariant,
  type Toolchains
} from "./model.js";

const rustTargets = [
  { id: "x64-gnullvm", target: "x86_64-pc-windows-gnullvm", vcArchitecture: null, linker: null },
  { id: "x86-gnullvm", target: "i686-pc-windows-gnullvm", vcArchitecture: null, linker: "gnullvm" },
  { id: "x64-gnu", target: "x86_64-pc-windows-gnu", vcArchitecture: null, linker: null },
  { id: "x86-gnu", target: "i686-pc-windows-gnu", vcArchitecture: null, linker: "gnu" },
  { id: "x64-msvc", target: "x86_64-pc-windows-msvc", vcArchitecture: "x64", linker: null },
  { id: "x86-msvc", target: "i686-pc-windows-msvc", vcArchitecture: "x86", linker: null }
] as const;

type RustTarget = (typeof rustTargets)[number];

const rustTargetCpuModes = ["x86-64-v2", "x86-64-v3", "native"] as const;

const optimizedAbortArgs = [
  "-C", "opt-level=3",
  "-C", "panic=abort",
  "-C", "debuginfo=0",
  "-C", "strip=symbols"
] as const;

const variantDirectory = (outputRoot: string, id: string): string =>
  join(outputRoot, "variants", id);

const outputPath = (outputRoot: string, id: string): string =>
  join(variantDirectory(outputRoot, id), `${id}.exe`);

const missing = (name: string, value: string | null): string[] =>
  value ? [] : [`${name} was not found.`];

const rustRuntimeLinkage = (id: string): string => {
  if (id.endsWith("-gnu")) return "Rust std static + Windows/UCRT DLLs";
  if (id.endsWith("-gnullvm")) return "Rust std static + libunwind/UCRT DLLs";
  return "Rust std static + MSVC/UCRT DLLs";
};

const sizeColumns = (
  target: RustTarget,
  mode: string
): BinarySizeTableColumns => {
  const [arch, abi] = target.id.split("-");
  return {
    arch: arch ?? "unknown",
    compiler: `rustc ${(abi ?? "unknown").toUpperCase()}`,
    mode,
    runtimeLinkage: rustRuntimeLinkage(target.id)
  };
};

const makeVariant = (
  outputRoot: string,
  id: string,
  label: string,
  sizeTableColumns: BinarySizeTableColumns,
  steps: BuildStep[],
  skipReasons: string[]
): BuildVariant => {
  const variant = {
    id,
    label,
    language: "rust" as const,
    outputPath: outputPath(outputRoot, id),
    sizeTableColumns,
    steps,
    toolchain: "rustc"
  };
  return skipReasons.length ? { ...variant, skipReason: skipReasons.join(" ") } : variant;
};

const directStep = (
  executable: string,
  args: string[],
  env: Record<string, string> | undefined
): BuildStep => {
  const step = { label: "compile", executable, args, cwd: projectRoot };
  return env ? { ...step, env } : step;
};

const rustLinkerMissing = (
  toolchains: Toolchains,
  linker: "gnu" | "gnullvm" | null
): string[] => {
  if (linker === "gnu") return missing("i686-w64-mingw32-gcc", toolchains.rustI686GnuLinker);
  if (linker === "gnullvm") return missing("i686-w64-mingw32-clang", toolchains.rustI686GnullvmLinker);
  return [];
};

const buildRustCompileVariant = (
  outputRoot: string,
  toolchains: Toolchains,
  sourcePath: string,
  target: RustTarget,
  idSuffix: string,
  label: string,
  modeArgs: readonly string[],
  linkerEnv: Record<string, string> | undefined
): BuildVariant => {
  const id = `rust-${target.id}-${idSuffix}`;
  const args = [sourcePath, "--target", target.target, ...modeArgs, "-o", outputPath(outputRoot, id)];
  const direct = toolchains.rustc ? [directStep(toolchains.rustc, args, linkerEnv)] : [];
  const steps = target.vcArchitecture && toolchains.rustc && toolchains.visualStudio
    ? [createVisualStudioStep("compile", toolchains.visualStudio, target.vcArchitecture, [[toolchains.rustc, ...args]])]
    : direct;
  const vsMissing = target.vcArchitecture
    ? missing("Visual Studio vcvarsall.bat", toolchains.visualStudio?.vcvarsallPath ?? null)
    : [];
  return makeVariant(outputRoot, id, label, sizeColumns(target, idSuffix), steps, [
    ...missing("rustc", toolchains.rustc),
    ...vsMissing,
    ...rustLinkerMissing(toolchains, target.linker)
  ]);
};

export const buildRustVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  sourcePath: string
): BuildVariant[] => {
  const variants: BuildVariant[] = [];
  const linkerDirectories = [
    toolchains.msysClang64.binDirectory,
    toolchains.msysUcrt64.binDirectory,
    "C:\\msys64\\usr\\bin"
  ].filter((directory): directory is string => Boolean(directory));
  const linkerEnv = linkerDirectories.length ? prependPath(linkerDirectories) : undefined;
  for (const target of rustTargets) {
    for (const optLevel of ["0", "3", "z"]) {
      for (const panicStrategy of ["unwind", "abort"]) {
        variants.push(buildRustCompileVariant(outputRoot, toolchains, sourcePath, target,
          `o${optLevel}-panic-${panicStrategy}`, target.target,
          [
            "-C", `opt-level=${optLevel}`,
            "-C", `panic=${panicStrategy}`,
            "-C", "debuginfo=0",
            "-C", "strip=symbols"
          ],
          linkerEnv));
      }
    }
    if (target.id.startsWith("x64")) {
      for (const cpu of rustTargetCpuModes) {
        variants.push(buildRustCompileVariant(outputRoot, toolchains, sourcePath, target,
          `o3-panic-abort-target-cpu-${cpu}`, `${target.target} target-cpu=${cpu}`,
          [...optimizedAbortArgs, "-C", `target-cpu=${cpu}`], linkerEnv));
      }
      variants.push(buildRustCompileVariant(outputRoot, toolchains, sourcePath, target,
        "o3-panic-abort-lto-thin", `${target.target} lto=thin`,
        [...optimizedAbortArgs, "-C", "lto=thin"], linkerEnv));
    }
  }
  return variants;
};
