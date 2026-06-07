"use strict";

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { basename, join } from "node:path";
import type { MsysToolchain, Toolchains, VisualStudioToolchain } from "./peDisassemblySamples-model.js";
import { projectRoot } from "./peDisassemblySamples-model.js";

interface CommandOutput {
  code: number;
  stdout: string;
}

const localAppData = process.env["LOCALAPPDATA"] ?? "";
const programFiles = process.env["ProgramFiles"] ?? "C:\\Program Files";
const programFilesX86 = process.env["ProgramFiles(x86)"] ?? "C:\\Program Files (x86)";

const runCommand = async (executable: string, args: string[]): Promise<CommandOutput> =>
  new Promise(resolveResult => {
    const child = spawn(executable, args, { cwd: projectRoot, windowsHide: true });
    let stdout = "";
    child.stdout.on("data", chunk => {
      stdout += String(chunk);
    });
    child.on("error", () => {
      resolveResult({ code: -1, stdout: "" });
    });
    child.on("close", code => {
      resolveResult({ code: code ?? -1, stdout });
    });
  });

const getPathDirectories = (): string[] =>
  (process.env["PATH"] ?? "").split(";").map(part => part.trim()).filter(Boolean);

const getExecutableNames = (name: string): string[] => {
  if (/\.[^.\\/:]+$/u.test(name)) return [name];
  return (process.env["PATHEXT"] ?? ".COM;.EXE;.BAT;.CMD").split(";").map(extension => `${name}${extension}`);
};

const findOnPath = (name: string): string | null => {
  for (const directory of getPathDirectories()) {
    for (const executableName of getExecutableNames(name)) {
      const candidate = join(directory, executableName);
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
};

const firstExisting = (paths: string[]): string | null =>
  paths.find(candidate => existsSync(candidate)) ?? null;

const findNestedFile = async (root: string, fileName: string, depth: number): Promise<string | null> => {
  if (!root || depth < 0 || !existsSync(root)) return null;
  const entries = await readdir(root, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    const child = join(root, entry.name);
    if (entry.isFile() && basename(child).toLowerCase() === fileName.toLowerCase()) return child;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const found = await findNestedFile(join(root, entry.name), fileName, depth - 1);
    if (found) return found;
  }
  return null;
};

const discoverVisualStudio = async (): Promise<VisualStudioToolchain | null> => {
  const vswhere = firstExisting([
    findOnPath("vswhere.exe") ?? "",
    join(programFilesX86, "Microsoft Visual Studio", "Installer", "vswhere.exe")
  ].filter(Boolean));
  const fallbackRoot = join(programFilesX86, "Microsoft Visual Studio", "18", "BuildTools");
  if (!vswhere) return buildVisualStudioFromRoot(fallbackRoot);
  const result = await runCommand(vswhere, [
    "-latest",
    "-products",
    "*",
    "-requires",
    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
    "-property",
    "installationPath"
  ]);
  return buildVisualStudioFromRoot(result.stdout.trim()) ?? buildVisualStudioFromRoot(fallbackRoot);
};

const buildVisualStudioFromRoot = (installationPath: string): VisualStudioToolchain | null => {
  const vcvarsallPath = join(installationPath, "VC", "Auxiliary", "Build", "vcvarsall.bat");
  if (!existsSync(vcvarsallPath)) return null;
  return { installationPath, vcvarsallPath };
};

const discoverMsysToolchain = (binDirectory: string): MsysToolchain => {
  const executable = (name: string): string | null => firstExisting([join(binDirectory, name)]);
  return {
    binDirectory: existsSync(binDirectory) ? binDirectory : null,
    gcc: executable("gcc.exe"),
    gxx: executable("g++.exe"),
    clang: executable("clang.exe"),
    clangxx: executable("clang++.exe"),
    lldLink: executable("lld-link.exe")
  };
};

export const discoverToolchains = async (): Promise<Toolchains> => {
  const wingetPackages = join(localAppData, "Microsoft", "WinGet", "Packages");
  const zig = firstExisting([
    findOnPath("zig.exe") ?? "",
    join(programFiles, "Zig", "zig.exe"),
    await findNestedFile(wingetPackages, "zig.exe", 3) ?? ""
  ].filter(Boolean));
  const nasm = firstExisting([
    findOnPath("nasm.exe") ?? "",
    join(localAppData, "bin", "NASM", "nasm.exe"),
    join(programFiles, "NASM", "nasm.exe")
  ].filter(Boolean));
  return {
    clang: firstExisting([findOnPath("clang.exe") ?? "", join(programFiles, "LLVM", "bin", "clang.exe")].filter(Boolean)),
    clangCl: firstExisting([findOnPath("clang-cl.exe") ?? "", join(programFiles, "LLVM", "bin", "clang-cl.exe")].filter(Boolean)),
    dmd: firstExisting([findOnPath("dmd.exe") ?? "", "C:\\D\\dmd2\\windows\\bin64\\dmd.exe"].filter(Boolean)),
    dotnet: findOnPath("dotnet.exe"),
    fpc: firstExisting([findOnPath("fpc.exe") ?? "", "C:\\FPC\\3.2.2\\bin\\i386-win32\\fpc.exe"].filter(Boolean)),
    go: findOnPath("go.exe"),
    lldLink: firstExisting([findOnPath("lld-link.exe") ?? "", join(programFiles, "LLVM", "bin", "lld-link.exe")].filter(Boolean)),
    nasm,
    rustc: findOnPath("rustc.exe"),
    rustI686GnuLinker: findOnPath("i686-w64-mingw32-gcc.exe"),
    rustI686GnullvmLinker: findOnPath("i686-w64-mingw32-clang.exe"),
    visualStudio: await discoverVisualStudio(),
    zig,
    msysClang64: discoverMsysToolchain("C:\\msys64\\clang64\\bin"),
    msysUcrt64: discoverMsysToolchain("C:\\msys64\\ucrt64\\bin")
  };
};
