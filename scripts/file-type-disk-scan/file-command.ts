"use strict";

import { spawn } from "node:child_process";

const DEFAULT_FILE_EXE = "C:\\Program Files\\Git\\usr\\bin\\file.exe";

const splitOutputLines = (value: string): string[] =>
  value.split(/\r?\n/u).filter(line => line.length > 0);

type FileCommandResult =
  | { status: "ok"; mimeType: string }
  | { status: "error"; message: string };

const parseFileOutput = (line: string): FileCommandResult => {
  const value = line.trim();
  // RFC 6838 section 4.2 limits both names to 127 restricted-name characters.
  // https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2
  if (/^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/iu.test(value)) {
    return { status: "ok", mimeType: value };
  }
  return { status: "error", message: value || "file.exe returned empty output." };
};

const errorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

const runFileCommand = async (fileExePath: string, paths: string[]): Promise<string[]> =>
  new Promise((resolve, reject) => {
    const child = spawn(fileExePath, ["-L", "-b", "--mime-type", "--", ...paths], {
      windowsHide: true
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", chunk => {
      stdout += chunk;
    });
    child.stderr.on("data", chunk => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", code => {
      const lines = splitOutputLines(stdout);
      if (code === 0 && lines.length === paths.length) resolve(lines);
      else reject(new Error(stderr.trim() || `file.exe returned ${code ?? "unknown"}.`));
    });
  });

const readSingleMimeType = async (
  fileExePath: string,
  path: string
): Promise<FileCommandResult> => {
  try {
    const [mimeType] = await runFileCommand(fileExePath, [path]);
    return parseFileOutput(mimeType ?? "");
  } catch (error) {
    return { status: "error", message: errorMessage(error) };
  }
};

const readFileMimeTypes = async (
  fileExePath: string,
  paths: string[]
): Promise<FileCommandResult[]> => {
  try {
    return (await runFileCommand(fileExePath, paths)).map(parseFileOutput);
  } catch {
    return Promise.all(paths.map(path => readSingleMimeType(fileExePath, path)));
  }
};

export { DEFAULT_FILE_EXE, parseFileOutput, readFileMimeTypes };
export type { FileCommandResult };
