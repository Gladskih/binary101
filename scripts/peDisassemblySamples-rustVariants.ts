"use strict";

import { join } from "node:path";
import { createVisualStudioStep, prependPath } from "./peDisassemblySamples-command.js";
import {
  projectRoot,
  type BuildStep,
  type BuildVariant,
  type Toolchains
} from "./peDisassemblySamples-model.js";

const rustTargets = [
  { id: "x64-gnullvm", target: "x86_64-pc-windows-gnullvm", vcArchitecture: null, linker: null },
  { id: "x86-gnullvm", target: "i686-pc-windows-gnullvm", vcArchitecture: null, linker: "gnullvm" },
  { id: "x64-gnu", target: "x86_64-pc-windows-gnu", vcArchitecture: null, linker: null },
  { id: "x86-gnu", target: "i686-pc-windows-gnu", vcArchitecture: null, linker: "gnu" },
  { id: "x64-msvc", target: "x86_64-pc-windows-msvc", vcArchitecture: "x64", linker: null },
  { id: "x86-msvc", target: "i686-pc-windows-msvc", vcArchitecture: "x86", linker: null }
] as const;

const variantDirectory = (outputRoot: string, id: string): string =>
  join(outputRoot, "variants", id);

const outputPath = (outputRoot: string, id: string): string =>
  join(variantDirectory(outputRoot, id), `${id}.exe`);

const missing = (name: string, value: string | null): string[] =>
  value ? [] : [`${name} was not found.`];

const makeVariant = (
  outputRoot: string,
  id: string,
  label: string,
  steps: BuildStep[],
  skipReasons: string[]
): BuildVariant => {
  const variant = { id, label, language: "rust" as const, outputPath: outputPath(outputRoot, id), steps, toolchain: "rustc" };
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
        const id = `rust-${target.id}-o${optLevel}-panic-${panicStrategy}`;
        const args = [sourcePath, "--target", target.target, "-C", `opt-level=${optLevel}`, "-C", `panic=${panicStrategy}`, "-C", "debuginfo=0", "-o", outputPath(outputRoot, id)];
        const direct = toolchains.rustc ? [directStep(toolchains.rustc, args, linkerEnv)] : [];
        const steps = target.vcArchitecture && toolchains.rustc && toolchains.visualStudio
          ? [createVisualStudioStep("compile", toolchains.visualStudio, target.vcArchitecture, [[toolchains.rustc, ...args]])]
          : direct;
        const vsMissing = target.vcArchitecture
          ? missing("Visual Studio vcvarsall.bat", toolchains.visualStudio?.vcvarsallPath ?? null)
          : [];
        variants.push(makeVariant(outputRoot, id, target.target, steps, [
          ...missing("rustc", toolchains.rustc),
          ...vsMissing,
          ...rustLinkerMissing(toolchains, target.linker)
        ]));
      }
    }
  }
  return variants;
};
