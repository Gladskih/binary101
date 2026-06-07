"use strict";

import { join } from "node:path";
import { createVisualStudioStep, prependPath } from "./command.js";
import {
  projectRoot,
  type BuildStep,
  type BuildVariant,
  type MsysToolchain,
  type SampleLanguage,
  type Toolchains
} from "./model.js";

type NativeLanguage = "c" | "cpp";
interface CompilerMode {
  args: string[];
  id: string;
  label: string;
}

const releaseModes: readonly CompilerMode[] = [
  { id: "o0", label: "O0", args: ["-O0"] },
  { id: "o2", label: "O2", args: ["-O2"] },
  { id: "os", label: "Os", args: ["-Os"] }
];

const cpuModes: readonly CompilerMode[] = [
  { id: "o2-march-x86-64-v2", label: "O2 -march=x86-64-v2", args: ["-O2", "-march=x86-64-v2"] },
  { id: "o2-march-x86-64-v3", label: "O2 -march=x86-64-v3", args: ["-O2", "-march=x86-64-v3"] },
  { id: "o2-mtune-znver5", label: "O2 -mtune=znver5", args: ["-O2", "-mtune=znver5"] },
  { id: "o2-march-znver5", label: "O2 -march=znver5", args: ["-O2", "-march=znver5"] }
];

const zigCpuModes: readonly CompilerMode[] = [
  { id: "o2-march-x86-64-v2", label: "O2 -march=x86_64_v2", args: ["-O2", "-march=x86_64_v2"] },
  { id: "o2-march-x86-64-v3", label: "O2 -march=x86_64_v3", args: ["-O2", "-march=x86_64_v3"] },
  { id: "o2-mtune-znver5", label: "O2 -mtune=znver5", args: ["-O2", "-mtune=znver5"] },
  { id: "o2-march-znver5", label: "O2 -march=znver5", args: ["-O2", "-march=znver5"] }
];

const ltoMode: CompilerMode = { id: "o2-flto", label: "O2 -flto", args: ["-O2", "-flto"] };

const msvcRuntimeModes: readonly CompilerMode[] = [
  { id: "od-md", label: "Od /MD", args: ["/Od", "/MD"] },
  { id: "o2-md", label: "O2 /MD", args: ["/O2", "/MD"] },
  { id: "o2-mt", label: "O2 /MT", args: ["/O2", "/MT"] }
];

const msvcExtraModes: readonly CompilerMode[] = [
  { id: "o2-md-ltcg", label: "O2 /MD /GL /LTCG", args: ["/O2", "/MD", "/GL", "/link", "/LTCG"] },
  { id: "o2-md-arch-avx2", label: "O2 /MD /arch:AVX2", args: ["/O2", "/MD", "/arch:AVX2"] },
  { id: "o2-md-arch-avx512", label: "O2 /MD /arch:AVX512", args: ["/O2", "/MD", "/arch:AVX512"] }
];

const clangClExtraModes: readonly CompilerMode[] = [
  { id: "o2-md-flto", label: "O2 /MD -flto", args: ["/O2", "/MD", "-flto"] },
  { id: "o2-md-march-x86-64-v2", label: "O2 /MD -march=x86-64-v2", args: ["/O2", "/MD", "-march=x86-64-v2"] },
  { id: "o2-md-march-x86-64-v3", label: "O2 /MD -march=x86-64-v3", args: ["/O2", "/MD", "-march=x86-64-v3"] },
  { id: "o2-md-mtune-znver5", label: "O2 /MD -mtune=znver5", args: ["/O2", "/MD", "-mtune=znver5"] },
  { id: "o2-md-march-znver5", label: "O2 /MD -march=znver5", args: ["/O2", "/MD", "-march=znver5"] }
];

const variantDirectory = (outputRoot: string, id: string): string =>
  join(outputRoot, "variants", id);

const outputPath = (outputRoot: string, id: string): string =>
  join(variantDirectory(outputRoot, id), `${id}.exe`);

const missing = (name: string, value: string | null): string[] =>
  value ? [] : [`${name} was not found.`];

const makeVariant = (
  outputRoot: string,
  id: string,
  language: SampleLanguage,
  toolchain: string,
  label: string,
  steps: BuildStep[],
  skipReasons: string[]
): BuildVariant => {
  const variant = { id, label, language, outputPath: outputPath(outputRoot, id), steps, toolchain };
  return skipReasons.length ? { ...variant, skipReason: skipReasons.join(" ") } : variant;
};

const directStep = (
  executable: string,
  args: string[],
  env?: Record<string, string>
): BuildStep => {
  const step = { label: "compile", executable, args, cwd: projectRoot };
  return env ? { ...step, env } : step;
};

const visualStudioCompileStep = (
  toolchains: Toolchains,
  architecture: string,
  executable: string,
  args: string[]
): BuildStep[] =>
  toolchains.visualStudio
    ? [createVisualStudioStep("compile", toolchains.visualStudio, architecture, [[executable, ...args]])]
    : [];

const msvcModesForArchitecture = (architecture: string): readonly CompilerMode[] =>
  architecture === "x64"
    ? [...msvcRuntimeModes, ...msvcExtraModes]
    : [...msvcRuntimeModes, msvcExtraModes[0]!];

const buildMsvcLanguageVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  language: NativeLanguage,
  sourcePath: string
): BuildVariant[] =>
  ["x64", "x86"].flatMap(architecture =>
    msvcModesForArchitecture(architecture).map(mode => {
      const id = `${language}-msvc-${architecture}-${mode.id}`;
      const args = [
        sourcePath,
        "/nologo",
        `/Fo:${variantDirectory(outputRoot, id)}\\`,
        `/Fe:${outputPath(outputRoot, id)}`,
        ...mode.args
      ];
      return makeVariant(outputRoot, id, language, "msvc-cl", `${architecture} ${mode.label}`,
        visualStudioCompileStep(toolchains, architecture, "cl.exe", args),
        missing("Visual Studio vcvarsall.bat", toolchains.visualStudio?.vcvarsallPath ?? null));
    })
  );

const clangClModesForArchitecture = (architecture: string): readonly CompilerMode[] =>
  architecture === "x64"
    ? [...msvcRuntimeModes, ...clangClExtraModes]
    : [...msvcRuntimeModes, clangClExtraModes[0]!];

const buildClangClLanguageVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  language: NativeLanguage,
  sourcePath: string
): BuildVariant[] =>
  ["x64", "x86"].flatMap(architecture =>
    clangClModesForArchitecture(architecture).map(mode => {
      const id = `${language}-clang-cl-${architecture}-${mode.id}`;
      const target = architecture === "x64" ? "x86_64-pc-windows-msvc" : "i686-pc-windows-msvc";
      const args = [
        `--target=${target}`,
        sourcePath,
        "/nologo",
        "-fuse-ld=lld",
        `/Fo:${variantDirectory(outputRoot, id)}\\`,
        `/Fe:${outputPath(outputRoot, id)}`,
        ...mode.args
      ];
      const steps = toolchains.clangCl
        ? visualStudioCompileStep(toolchains, architecture, toolchains.clangCl, args)
        : [];
      const skipReasons = [
        ...missing("clang-cl", toolchains.clangCl),
        ...missing("Visual Studio vcvarsall.bat", toolchains.visualStudio?.vcvarsallPath ?? null)
      ];
      return makeVariant(outputRoot, id, language, "llvm-clang-cl", `${architecture} ${mode.label}`,
        steps, skipReasons);
    })
  );

const buildDirectGccStyleVariants = (
  outputRoot: string,
  compiler: string | null,
  env: Record<string, string> | undefined,
  language: NativeLanguage,
  sourcePath: string,
  family: string,
  ltoExtraArgs: string[]
): BuildVariant[] =>
  [...releaseModes, ...cpuModes, { ...ltoMode, args: [...ltoMode.args, ...ltoExtraArgs] }].map(mode => {
    const id = `${language}-${family}-x64-${mode.id}`;
    const args = [sourcePath, "-o", outputPath(outputRoot, id), ...mode.args];
    const steps = compiler ? [directStep(compiler, args, env)] : [];
    return makeVariant(outputRoot, id, language, family, `x64 ${mode.label}`, steps,
      missing(`${family} ${language} compiler`, compiler));
  });

const buildMsysGccLanguageVariants = (
  outputRoot: string,
  toolchain: MsysToolchain,
  language: NativeLanguage,
  sourcePath: string
): BuildVariant[] => {
  const compiler = language === "c" ? toolchain.gcc : toolchain.gxx;
  const env = toolchain.binDirectory ? prependPath([toolchain.binDirectory, "C:\\msys64\\usr\\bin"]) : undefined;
  return buildDirectGccStyleVariants(outputRoot, compiler, env, language, sourcePath, "msys-ucrt64", []);
};

const buildMsysClangLanguageVariants = (
  outputRoot: string,
  toolchain: MsysToolchain,
  language: NativeLanguage,
  sourcePath: string,
  family: string
): BuildVariant[] => {
  const compiler = language === "c" ? toolchain.clang : toolchain.clangxx;
  const env = toolchain.binDirectory ? prependPath([toolchain.binDirectory, "C:\\msys64\\usr\\bin"]) : undefined;
  return buildDirectGccStyleVariants(outputRoot, compiler, env, language, sourcePath, family, ["-fuse-ld=lld"]);
};

const buildLlvmClangMsvcLanguageVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  language: NativeLanguage,
  sourcePath: string
): BuildVariant[] => {
  const compiler = language === "c" ? toolchains.clang : toolchains.clangxx;
  const compilerName = language === "c" ? "clang" : "clang++";
  return [
    ...["x64", "x86"].flatMap(architecture =>
      releaseModes.map(mode =>
        buildLlvmClangMsvcVariant(outputRoot, toolchains, language, sourcePath, compiler,
          compilerName, architecture, mode))
    ),
    ...[...cpuModes, ltoMode].map(mode =>
      buildLlvmClangMsvcVariant(outputRoot, toolchains, language, sourcePath, compiler,
        compilerName, "x64", mode))
  ];
};

const buildLlvmClangMsvcVariant = (
  outputRoot: string,
  toolchains: Toolchains,
  language: NativeLanguage,
  sourcePath: string,
  compiler: string | null,
  compilerName: string,
  architecture: string,
  mode: CompilerMode
): BuildVariant => {
  const id = `${language}-llvm-clang-msvc-${architecture}-${mode.id}`;
  const target = architecture === "x64" ? "x86_64-pc-windows-msvc" : "i686-pc-windows-msvc";
  const args = [`--target=${target}`, sourcePath, "-fuse-ld=lld", "-o", outputPath(outputRoot, id), ...mode.args];
  const steps = compiler ? visualStudioCompileStep(toolchains, architecture, compiler, args) : [];
  return makeVariant(outputRoot, id, language, "llvm-clang", `${architecture} ${mode.label}`, steps, [
    ...missing(compilerName, compiler),
    ...missing("Visual Studio vcvarsall.bat", toolchains.visualStudio?.vcvarsallPath ?? null)
  ]);
};

const buildZigCcLanguageVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  language: NativeLanguage,
  sourcePath: string
): BuildVariant[] => {
  const baseVariants = ["x86_64-windows-gnu", "x86-windows-gnu"].flatMap(target =>
    releaseModes.slice(0, 2).map(mode =>
      buildZigCcVariant(outputRoot, toolchains, language, sourcePath, target, mode))
  );
  const cpuVariants = zigCpuModes.map(mode =>
    buildZigCcVariant(outputRoot, toolchains, language, sourcePath, "x86_64-windows-gnu", mode)
  );
  return [...baseVariants, ...cpuVariants];
};

const buildZigCcVariant = (
  outputRoot: string,
  toolchains: Toolchains,
  language: NativeLanguage,
  sourcePath: string,
  target: string,
  mode: CompilerMode
): BuildVariant => {
  const architecture = target.startsWith("x86_64") ? "x64" : "x86";
  const id = `${language}-zig-cc-${architecture}-${mode.id}`;
  const args = [
    language === "c" ? "cc" : "c++",
    sourcePath,
    "-target",
    target,
    "-o",
    outputPath(outputRoot, id),
    ...mode.args
  ];
  const steps = toolchains.zig ? [directStep(toolchains.zig, args)] : [];
  return makeVariant(outputRoot, id, language, "zig-cc", `${target} ${mode.label}`,
    steps, missing("zig", toolchains.zig));
};

export const buildNativeLanguageVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  language: NativeLanguage,
  sourcePath: string
): BuildVariant[] => [
  ...buildMsvcLanguageVariants(outputRoot, toolchains, language, sourcePath),
  ...buildClangClLanguageVariants(outputRoot, toolchains, language, sourcePath),
  ...buildMsysGccLanguageVariants(outputRoot, toolchains.msysUcrt64, language, sourcePath),
  ...buildMsysClangLanguageVariants(outputRoot, toolchains.msysUcrt64, language, sourcePath, "msys-ucrt64-clang"),
  ...buildMsysClangLanguageVariants(outputRoot, toolchains.msysClang64, language, sourcePath, "msys-clang64"),
  ...buildLlvmClangMsvcLanguageVariants(outputRoot, toolchains, language, sourcePath),
  ...buildZigCcLanguageVariants(outputRoot, toolchains, language, sourcePath)
];
