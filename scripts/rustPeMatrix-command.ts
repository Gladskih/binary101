"use strict";

import { spawn } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import {
  projectRoot,
  rustcExecutable,
  type CommandResult,
  type VariantSpec
} from "./rustPeMatrix-model.js";

export const runCommand = async (
  command: string,
  args: string[],
  cwd: string
): Promise<CommandResult> =>
  new Promise((resolveResult, reject) => {
    const startedAt = Date.now();
    const child = spawn(command, args, { cwd, windowsHide: true });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", chunk => {
      stdout += String(chunk);
    });
    child.stderr.on("data", chunk => {
      stderr += String(chunk);
    });
    child.on("error", reject);
    child.on("close", code => {
      resolveResult({
        code: code ?? -1,
        stdout,
        stderr,
        durationMs: Date.now() - startedAt
      });
    });
  });

export const getHostTarget = async (): Promise<string> => {
  const version = await runCommand(rustcExecutable, ["-vV"], projectRoot);
  const hostLine = version.stdout.split(/\r?\n/u).find(line => line.startsWith("host: "));
  if (!hostLine) throw new Error("rustc -vV did not report a host target.");
  return hostLine.slice("host: ".length).trim();
};

export const getInstalledRustStdTargets = async (): Promise<string[]> => {
  const sysroot = await runCommand(rustcExecutable, ["--print", "sysroot"], projectRoot);
  if (sysroot.code !== 0) {
    throw new Error(`rustc --print sysroot failed: ${sysroot.stderr}`);
  }
  const rustlibDirectory = join(sysroot.stdout.trim(), "lib", "rustlib");
  const entries = await readdir(rustlibDirectory, { withFileTypes: true });
  return entries
    .filter(entry => entry.isDirectory() && entry.name !== "etc")
    .map(entry => entry.name)
    .sort();
};

export const toRustcArgs = (
  sourcePath: string,
  outputPath: string,
  variant: VariantSpec
): string[] => [sourcePath, "--target", variant.target, "-o", outputPath, ...variant.rustcArgs];

const quoteArg = (value: string): string =>
  /[\s"]/u.test(value) ? `"${value.replaceAll("\"", '\\"')}"` : value;

export const toCommandLine = (command: string, args: string[]): string =>
  [command, ...args].map(quoteArg).join(" ");
