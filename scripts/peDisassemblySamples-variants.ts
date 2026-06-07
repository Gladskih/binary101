"use strict";

import { dirname, join } from "node:path";
import { createVisualStudioStep, prependPath, toCommandLine } from "./peDisassemblySamples-command.js";
import { buildAssemblyVariants } from "./peDisassemblySamples-assemblyVariants.js";
import { buildRustVariants } from "./peDisassemblySamples-rustVariants.js";
import {
  projectRoot,
  sampleSourceRoot,
  type BuildStep,
  type BuildVariant,
  type MsysToolchain,
  type SampleLanguage,
  type SampleSources,
  type Toolchains
} from "./peDisassemblySamples-model.js";

const releaseModes = [
  { id: "o0", label: "O0", args: ["-O0"] },
  { id: "o2", label: "O2", args: ["-O2"] },
  { id: "os", label: "Os", args: ["-Os"] }
] as const;
export const getSampleSources = (): SampleSources => ({
  assemblyMasmX64: join(sampleSourceRoot, "assembly", "hello-masm-x64.asm"),
  assemblyMasmX86: join(sampleSourceRoot, "assembly", "hello-masm-x86.asm"),
  assemblyNasmX64: join(sampleSourceRoot, "assembly", "hello-nasm-x64.asm"),
  assemblyNasmX86: join(sampleSourceRoot, "assembly", "hello-nasm-x86.asm"),
  c: join(sampleSourceRoot, "c", "hello.c"),
  cpp: join(sampleSourceRoot, "cpp", "hello.cpp"),
  csharpProject: join(sampleSourceRoot, "csharp", "HelloCSharp.csproj"),
  d: join(sampleSourceRoot, "d", "hello.d"),
  go: join(sampleSourceRoot, "go", "hello.go"),
  pascal: join(sampleSourceRoot, "pascal", "hello.pas"),
  rust: join(sampleSourceRoot, "rust", "hello.rs"),
  zig: join(sampleSourceRoot, "zig", "hello.zig")
});
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
  label: string,
  executable: string,
  args: string[],
  cwd: string = projectRoot,
  env?: Record<string, string>
): BuildStep => {
  const step = { label, executable, args, cwd };
  return env ? { ...step, env } : step;
};
const visualStudioCompileStep = (
  toolchains: Toolchains,
  architecture: string,
  executable: string,
  args: string[]
): BuildStep[] =>
  toolchains.visualStudio ? [
    createVisualStudioStep("compile", toolchains.visualStudio, architecture, [[executable, ...args]])
  ] : [];
const msvcRuntimeModes = [
  { id: "od-md", label: "Od /MD", args: ["/Od", "/MD"] },
  { id: "o2-md", label: "O2 /MD", args: ["/O2", "/MD"] },
  { id: "o2-mt", label: "O2 /MT", args: ["/O2", "/MT"] }
] as const;
const buildMsvcLanguageVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  language: "c" | "cpp",
  sourcePath: string
): BuildVariant[] => {
  const variants: BuildVariant[] = [];
  for (const architecture of ["x64", "x86"]) {
    for (const mode of msvcRuntimeModes) {
      const id = `${language}-msvc-${architecture}-${mode.id}`;
      const args = [sourcePath, "/nologo", `/Fo:${variantDirectory(outputRoot, id)}\\`, `/Fe:${outputPath(outputRoot, id)}`, ...mode.args];
      variants.push(makeVariant(outputRoot, id, language, "msvc-cl", `${architecture} ${mode.label}`, visualStudioCompileStep(toolchains, architecture, "cl.exe", args), missing("Visual Studio vcvarsall.bat", toolchains.visualStudio?.vcvarsallPath ?? null)));
    }
  }
  return variants;
};
const buildClangClLanguageVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  language: "c" | "cpp",
  sourcePath: string
): BuildVariant[] => {
  const variants: BuildVariant[] = [];
  for (const architecture of ["x64", "x86"]) {
    for (const mode of msvcRuntimeModes) {
      const id = `${language}-clang-cl-${architecture}-${mode.id}`;
      const target = architecture === "x64" ? "x86_64-pc-windows-msvc" : "i686-pc-windows-msvc";
      const args = [sourcePath, "/nologo", "-fuse-ld=lld", `/Fo:${variantDirectory(outputRoot, id)}\\`, `/Fe:${outputPath(outputRoot, id)}`, ...mode.args];
      args.unshift(`--target=${target}`);
      const steps = toolchains.clangCl
        ? visualStudioCompileStep(toolchains, architecture, toolchains.clangCl, args)
        : [];
      const skipReasons = [
        ...missing("clang-cl", toolchains.clangCl),
        ...missing("Visual Studio vcvarsall.bat", toolchains.visualStudio?.vcvarsallPath ?? null)
      ];
      variants.push(makeVariant(outputRoot, id, language, "llvm-clang-cl", `${architecture} ${mode.label}`, steps, skipReasons));
    }
  }
  return variants;
};
const buildMsysLanguageVariants = (
  outputRoot: string,
  toolchain: MsysToolchain,
  language: "c" | "cpp",
  sourcePath: string,
  family: string
): BuildVariant[] => {
  const compiler = language === "c" ? toolchain.gcc ?? toolchain.clang : toolchain.gxx ?? toolchain.clangxx;
  const env = toolchain.binDirectory ? prependPath([toolchain.binDirectory, "C:\\msys64\\usr\\bin"]) : undefined;
  return releaseModes.map(mode => {
    const id = `${language}-${family}-x64-${mode.id}`;
    const args = [sourcePath, "-o", outputPath(outputRoot, id), ...mode.args];
    return makeVariant(outputRoot, id, language, family, `x64 ${mode.label}`, compiler ? [directStep("compile", compiler, args, projectRoot, env)] : [], missing(`${family} ${language} compiler`, compiler ?? null));
  });
};
const buildZigCcLanguageVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  language: "c" | "cpp",
  sourcePath: string
): BuildVariant[] => {
  const variants: BuildVariant[] = [];
  for (const target of ["x86_64-windows-gnu", "x86-windows-gnu"]) {
    for (const mode of releaseModes.slice(0, 2)) {
      const id = `${language}-zig-cc-${target.startsWith("x86_64") ? "x64" : "x86"}-${mode.id}`;
      const args = [language === "c" ? "cc" : "c++", sourcePath, "-target", target, "-o", outputPath(outputRoot, id), ...mode.args];
      variants.push(makeVariant(outputRoot, id, language, "zig-cc", `${target} ${mode.label}`, toolchains.zig ? [directStep("compile", toolchains.zig, args)] : [], missing("zig", toolchains.zig)));
    }
  }
  return variants;
};
const buildNativeLanguageVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  language: "c" | "cpp",
  sourcePath: string
): BuildVariant[] => [
  ...buildMsvcLanguageVariants(outputRoot, toolchains, language, sourcePath),
  ...buildClangClLanguageVariants(outputRoot, toolchains, language, sourcePath),
  ...buildMsysLanguageVariants(outputRoot, toolchains.msysUcrt64, language, sourcePath, "msys-ucrt64"),
  ...buildMsysLanguageVariants(outputRoot, toolchains.msysClang64, language, sourcePath, "msys-clang64"),
  ...buildZigCcLanguageVariants(outputRoot, toolchains, language, sourcePath)
];
const buildGoVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  sourcePath: string
): BuildVariant[] => {
  const variants: BuildVariant[] = [];
  for (const architecture of ["amd64", "386"]) {
    for (const mode of [{ id: "default", args: [] }, { id: "noopt", args: ["-gcflags=all=-N -l"] }]) {
      const id = `go-windows-${architecture}-${mode.id}`;
      const env = { GOOS: "windows", GOARCH: architecture, CGO_ENABLED: "0" };
      const args = ["build", "-trimpath", "-o", outputPath(outputRoot, id), ...mode.args, sourcePath];
      variants.push(makeVariant(outputRoot, id, "go", "go", `${architecture} ${mode.id}`, toolchains.go ? [directStep("compile", toolchains.go, args, dirname(sourcePath), env)] : [], missing("go", toolchains.go)));
    }
  }
  return variants;
};
const buildZigVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  sourcePath: string
): BuildVariant[] =>
  ["Debug", "ReleaseFast", "ReleaseSmall"].flatMap(mode =>
    ["x86_64-windows-gnu", "x86-windows-gnu"].map(target => {
      const id = `zig-${target.startsWith("x86_64") ? "x64" : "x86"}-${mode.toLowerCase()}`;
      const args = ["build-exe", sourcePath, "-target", target, "-O", mode, `-femit-bin=${outputPath(outputRoot, id)}`];
      return makeVariant(outputRoot, id, "zig", "zig", `${target} ${mode}`, toolchains.zig ? [directStep("compile", toolchains.zig, args)] : [], missing("zig", toolchains.zig));
    })
  );
const buildCsharpVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  projectPath: string
): BuildVariant[] => [{
  runtime: "win-x64",
  configuration: "Release",
  flavor: "framework",
  extra: ["--self-contained", "false"]
}, {
  runtime: "win-x86",
  configuration: "Release",
  flavor: "selfcontained",
  extra: ["--self-contained", "true"]
}, {
  runtime: "win-x64",
  configuration: "Release",
  flavor: "nativeaot",
  extra: ["--self-contained", "true", "-p:PublishAot=true"]
}].map(({ runtime, configuration, flavor, extra }) => {
  const id = `csharp-${flavor}-${runtime.toLowerCase()}-${configuration.toLowerCase()}`;
  const publishDirectory = join(variantDirectory(outputRoot, id), "publish");
  const objectDirectory = join(variantDirectory(outputRoot, id), "obj");
  const binaryDirectory = join(variantDirectory(outputRoot, id), "bin");
  const env = { DOTNET_CLI_TELEMETRY_OPTOUT: "1", DOTNET_NOLOGO: "1", DOTNET_SKIP_FIRST_TIME_EXPERIENCE: "1" };
  const args = [
    "publish", projectPath, "--nologo", "-c", configuration, "-r", runtime, "-o", publishDirectory,
    "-p:RestoreIgnoreFailedSources=true", `-p:BaseIntermediateOutputPath=${objectDirectory}\\`,
    `-p:MSBuildProjectExtensionsPath=${objectDirectory}\\`, `-p:BaseOutputPath=${binaryDirectory}\\`,
    ...extra
  ];
  const steps = toolchains.dotnet ? [directStep("compile", toolchains.dotnet, args, projectRoot, env)] : [];
  const variant = makeVariant(outputRoot, id, "csharp", "dotnet", `${runtime} ${flavor}`, steps, missing("dotnet", toolchains.dotnet));
  return { ...variant, outputPath: join(publishDirectory, "HelloCSharp.exe") };
});
const buildPascalVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  sourcePath: string
): BuildVariant[] =>
  ["1", "3"].map(level => {
    const id = `pascal-fpc-win32-o${level}`;
    const args = ["-Twin32", "-Pi386", `-O${level}`, `-FE${variantDirectory(outputRoot, id)}`, `-o${outputPath(outputRoot, id)}`, sourcePath];
    return makeVariant(outputRoot, id, "pascal", "fpc", `win32 O${level}`, toolchains.fpc ? [directStep("compile", toolchains.fpc, args)] : [], missing("fpc", toolchains.fpc));
  });

const buildDVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  sourcePath: string
): BuildVariant[] =>
  [
    { id: "x64-debug", args: ["-m64"] },
    { id: "x64-release", args: ["-m64", "-O", "-release", "-inline", "-boundscheck=off"] },
    { id: "x86-mscoff-release", args: ["-m32mscoff", "-O", "-release", "-inline", "-boundscheck=off"] }
  ].map(mode => {
    const id = `d-dmd-${mode.id}`;
    const args = [sourcePath, `-of=${outputPath(outputRoot, id)}`, ...mode.args];
    return makeVariant(outputRoot, id, "d", "dmd", mode.id, toolchains.dmd ? [directStep("compile", toolchains.dmd, args)] : [], missing("dmd", toolchains.dmd));
  });

export const buildSampleVariants = (
  toolchains: Toolchains,
  outputRoot: string,
  sources: SampleSources = getSampleSources()
): BuildVariant[] => [
  ...buildNativeLanguageVariants(outputRoot, toolchains, "c", sources.c),
  ...buildNativeLanguageVariants(outputRoot, toolchains, "cpp", sources.cpp),
  ...buildRustVariants(outputRoot, toolchains, sources.rust),
  ...buildGoVariants(outputRoot, toolchains, sources.go),
  ...buildZigVariants(outputRoot, toolchains, sources.zig),
  ...buildCsharpVariants(outputRoot, toolchains, sources.csharpProject),
  ...buildPascalVariants(outputRoot, toolchains, sources.pascal),
  ...buildDVariants(outputRoot, toolchains, sources.d),
  ...buildAssemblyVariants(outputRoot, toolchains, sources)
];

export const buildCommandLines = (variant: BuildVariant): string[] =>
  variant.steps.map(step => step.display ?? toCommandLine(step.executable, step.args));
