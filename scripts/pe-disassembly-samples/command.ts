"use strict";

import { spawn } from "node:child_process";
import type { BuildStep, StepResult, VisualStudioToolchain } from "./model.js";

export const quoteCommandPart = (value: string): string =>
  /[\s"]/u.test(value) ? `"${value.replaceAll("\"", "\\\"")}"` : value;

export const toCommandLine = (executable: string, args: string[]): string =>
  [executable, ...args].map(quoteCommandPart).join(" ");

const mergeEnv = (env: Record<string, string> | undefined): Record<string, string | undefined> => ({
  ...process.env,
  ...env
});

export const prependPath = (
  directories: string[],
  env: Record<string, string | undefined> = process.env
): Record<string, string> => ({
  PATH: [...directories, env["PATH"] ?? ""].filter(Boolean).join(";")
});

export const createVisualStudioStep = (
  label: string,
  visualStudio: VisualStudioToolchain,
  architecture: string,
  commands: string[][]
): BuildStep => {
  const script = [
    `call ${quoteCommandPart(visualStudio.vcvarsallPath)} ${architecture} >nul`,
    ...commands.map(command => toCommandLine(command[0] ?? "", command.slice(1)))
  ].join(" && ");
  return {
    label,
    executable: "cmd.exe",
    args: ["/d", "/s", "/c", script],
    cwd: process.cwd(),
    display: script,
    windowsVerbatimArguments: true
  };
};

export const getStepCommandLine = (step: BuildStep): string =>
  step.display ?? toCommandLine(step.executable, step.args);

export const runStep = async (step: BuildStep): Promise<StepResult> =>
  new Promise(resolveResult => {
    const startedAt = Date.now();
    const child = spawn(step.executable, step.args, {
      cwd: step.cwd,
      env: mergeEnv(step.env),
      windowsHide: true,
      windowsVerbatimArguments: step.windowsVerbatimArguments
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", chunk => {
      stdout += String(chunk);
    });
    child.stderr.on("data", chunk => {
      stderr += String(chunk);
    });
    child.on("error", error => {
      resolveResult({
        code: -1,
        durationMs: Date.now() - startedAt,
        label: step.label,
        stderr: error.message,
        stdout
      });
    });
    child.on("close", code => {
      resolveResult({
        code: code ?? -1,
        durationMs: Date.now() - startedAt,
        label: step.label,
        stderr,
        stdout
      });
    });
  });
