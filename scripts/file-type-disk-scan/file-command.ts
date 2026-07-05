"use strict";

import { spawn } from "node:child_process";

const DEFAULT_FILE_EXE = "C:\\Program Files\\Git\\usr\\bin\\file.exe";

const splitOutputLines = (value: string): string[] =>
  value.split(/\r?\n/u).filter(line => line.length > 0);

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

const readSingleMimeType = async (fileExePath: string, path: string): Promise<string | null> => {
  try {
    const [mimeType] = await runFileCommand(fileExePath, [path]);
    return mimeType ?? null;
  } catch {
    return null;
  }
};

const readFileMimeTypes = async (fileExePath: string, paths: string[]): Promise<Array<string | null>> => {
  try {
    return await runFileCommand(fileExePath, paths);
  } catch {
    return Promise.all(paths.map(path => readSingleMimeType(fileExePath, path)));
  }
};

export { DEFAULT_FILE_EXE, readFileMimeTypes };
