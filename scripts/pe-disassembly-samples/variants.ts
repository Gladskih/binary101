"use strict";

import { dirname, join } from "node:path";
import { toCommandLine } from "./command.js";
import { buildAssemblyVariants } from "./assembly-variants.js";
import { buildNativeLanguageVariants } from "./native-variants.js";
import { buildRustVariants } from "./rust-variants.js";
import {
  projectRoot,
  sampleSourceRoot,
  type BuildStep,
  type BuildVariant,
  type SampleLanguage,
  type SampleSources,
  type Toolchains
} from "./model.js";

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
const buildGoVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  sourcePath: string
): BuildVariant[] => {
  const variants: BuildVariant[] = [];
  for (const architecture of ["amd64", "386"]) {
    const modes = architecture === "amd64"
      ? [
        { id: "default", args: [], env: {} },
        { id: "noopt", args: ["-gcflags=all=-N -l"], env: {} },
        { id: "goamd64-v3", args: [], env: { GOAMD64: "v3" } },
        { id: "goamd64-v4", args: [], env: { GOAMD64: "v4" } }
      ]
      : [
        { id: "default", args: [], env: {} },
        { id: "noopt", args: ["-gcflags=all=-N -l"], env: {} }
      ];
    for (const mode of modes) {
      const id = `go-windows-${architecture}-${mode.id}`;
      const env = { GOOS: "windows", GOARCH: architecture, CGO_ENABLED: "0", ...mode.env };
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
  runtime: "win-x64",
  configuration: "Release",
  flavor: "readytorun",
  extra: ["--self-contained", "false", "-p:PublishReadyToRun=true"]
}, {
  runtime: "win-x64",
  configuration: "Release",
  flavor: "readytorun-singlefile",
  extra: ["--self-contained", "false", "-p:PublishReadyToRun=true", "-p:PublishSingleFile=true"]
}, {
  runtime: "win-x64",
  configuration: "Release",
  flavor: "readytorun-selfcontained-singlefile",
  extra: ["--self-contained", "true", "-p:PublishReadyToRun=true", "-p:PublishSingleFile=true"]
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
}, {
  runtime: "win-x86",
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
