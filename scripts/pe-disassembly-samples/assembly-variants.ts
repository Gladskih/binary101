"use strict";

import { join } from "node:path";
import { createVisualStudioStep } from "./command.js";
import {
  projectRoot,
  type BuildStep,
  type BuildVariant,
  type SampleSources,
  type Toolchains
} from "./model.js";

const variantDirectory = (outputRoot: string, id: string): string =>
  join(outputRoot, "variants", id);

const outputPath = (outputRoot: string, id: string): string =>
  join(variantDirectory(outputRoot, id), `${id}.exe`);

const missing = (name: string, value: string | null): string[] =>
  value ? [] : [`${name} was not found.`];

const directStep = (label: string, executable: string, args: string[]): BuildStep => ({
  label,
  executable,
  args,
  cwd: projectRoot
});

const makeVariant = (
  outputRoot: string,
  id: string,
  toolchain: string,
  label: string,
  steps: BuildStep[],
  skipReasons: string[]
): BuildVariant => {
  const variant = {
    id,
    label,
    language: "assembly" as const,
    outputPath: outputPath(outputRoot, id),
    steps,
    toolchain
  };
  return skipReasons.length ? { ...variant, skipReason: skipReasons.join(" ") } : variant;
};

const buildNasmVariant = (
  outputRoot: string,
  toolchains: Toolchains,
  architecture: "x64" | "x86",
  format: string,
  sourcePath: string
): BuildVariant => {
  const id = `assembly-nasm-${architecture}-lld`;
  const objectPath = join(variantDirectory(outputRoot, id), `${id}.obj`);
  const machine = architecture === "x64" ? "x64" : "x86";
  const steps = toolchains.nasm && toolchains.lldLink ? [
    directStep("assemble", toolchains.nasm, ["-f", format, sourcePath, "-o", objectPath]),
    directStep("link", toolchains.lldLink, [
      objectPath, "/subsystem:console", "/entry:mainCRTStartup", `/machine:${machine}`,
      "/defaultlib:kernel32", `/out:${outputPath(outputRoot, id)}`
    ])
  ] : [];
  return makeVariant(outputRoot, id, "nasm+lld-link", `${architecture} direct WinAPI`, steps, [
    ...missing("nasm", toolchains.nasm),
    ...missing("lld-link", toolchains.lldLink)
  ]);
};

const buildMasmVariant = (
  outputRoot: string,
  toolchains: Toolchains,
  architecture: "x64" | "x86",
  sourcePath: string
): BuildVariant => {
  const id = `assembly-masm-${architecture}-link`;
  const objectPath = join(variantDirectory(outputRoot, id), `${id}.obj`);
  const assembler = architecture === "x64" ? "ml64.exe" : "ml.exe";
  const machine = architecture === "x64" ? "x64" : "x86";
  const commands = [
    [assembler, "/nologo", "/c", `/Fo${objectPath}`, sourcePath],
    [
      "link.exe", "/nologo", objectPath, "/subsystem:console", "/entry:mainCRTStartup",
      `/machine:${machine}`, "/defaultlib:kernel32", `/out:${outputPath(outputRoot, id)}`
    ]
  ];
  const steps = toolchains.visualStudio
    ? [createVisualStudioStep("assemble and link", toolchains.visualStudio, architecture, commands)]
    : [];
  return makeVariant(outputRoot, id, "masm+link", `${architecture} direct WinAPI`, steps, missing(
    "Visual Studio vcvarsall.bat",
    toolchains.visualStudio?.vcvarsallPath ?? null
  ));
};

export const buildAssemblyVariants = (
  outputRoot: string,
  toolchains: Toolchains,
  sources: SampleSources
): BuildVariant[] => [
  buildNasmVariant(outputRoot, toolchains, "x64", "win64", sources.assemblyNasmX64),
  buildNasmVariant(outputRoot, toolchains, "x86", "win32", sources.assemblyNasmX86),
  buildMasmVariant(outputRoot, toolchains, "x64", sources.assemblyMasmX64),
  buildMasmVariant(outputRoot, toolchains, "x86", sources.assemblyMasmX86)
];
